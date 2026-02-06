Analisi del codice
1. Installazione delle dipendenze
Scopo: Installa le librerie necessarie per caricare e usare un modello linguistico ottimizzato (Unsloth) e per la gestione di modelli di trasformatori (Hugging Face).
Dettagli:
•	unsloth : Libreria per caricare modelli linguistici grandi in modo efficiente (quantizzazione a 4 bit).
•	transformers e trl : Per la gestione e il fine-tuning di modelli linguistici.
•	bitsandbytes, xformers, peft : Ottimizzazioni per l’inferenza e il training su GPU.
•	La logica di installazione cambia se il codice gira su Google Colab o meno.

 

2. Caricamento del modello linguistico
•	Scopo: Carica un modello linguistico pre-addestrato (Llama-3.2-3B) in modalità inferenza, ottimizzato per l’uso di memoria (4 bit).
•	Dettagli: Il modello è pronto per generare risposte a prompt di testo. Viene usato per simulare le decisioni di un analista SOC.

 

3. Definizione della Catena di Markov (Stati e Azioni)
•	Scopo: Definisce uno spazio di stati che rappresentano le fasi di un attacco APT e le possibili azioni dell’analista.
•	Struttura:
o	Ogni stato ha:
	desc : Descrizione della situazione corrente.
	actions : Liste di azioni possibili.
	next : Mappatura tra indice dell’azione scelta e il prossimo stato.
o	Gli stati terminali (end_success, end_fail, etc.) indicano l’esito della simulazione.
•	Esempio: Da step0 (traffico anomalo), l’agente può scegliere tra 3 azioni, ognuna delle quali porta a un nuovo stato (es. step1_ip o step1_scan).


states = {
    "step0": {
        "desc": "Rilevato traffico anomalo verso un IP in Russia (185.143.223.42) dalle workstation del reparto ingegneria. Nessun allarme dai sistemi antivirus, ma il traffico è cifrato e persistente da 3 giorni.",
        "actions": [
            "Richiedi dettagli sull’IP e sul tipo di traffico.",
            "Esegui una scansione approfondita sulle workstation coinvolte.",
            "Fai un rapporto: sospetto attacco APT in corso."
        ],
        "next": {0: "step1_ip", 1: "step1_scan", 2: "end_fail"}
    },
    "step1_ip": {
        "desc": "L’IP 185.143.223.42 è associato a un server C2 noto, precedentemente utilizzato dal gruppo APT29 (Cozy Bear). Il traffico è compatibile con il protocollo di comando e controllo di malware custom.",
        "actions": [
            "Richiedi informazioni su APT29 e le loro TTP (Tactics, Techniques, Procedures).",
            "Analizza i log delle workstation per trovare file sospetti.",
            "Fai un rapporto: attacco APT29 confermato."
        ],
        "next": {0: "step2_ttp", 1: "step2_logs", 2: "end_success"}
    },
    "step1_scan": {
        "desc": "Trovato un file sospetto: energyschedule.exe (firmato digitalmente, ma con hash sconosciuto). Il file comunica con l’IP russo e ha creato una backdoor.",
        "actions": [
            "Richiedi analisi statica e dinamica del file.",
            "Isola le workstation e blocca il traffico verso l’IP.",
            "Fai un rapporto: malware custom, probabilmente APT."
        ],
        "next": {0: "step2_file_analysis", 1: "end_partial", 2: "end_success"}
    },
    "step2_ttp": {
        "desc": "APT29 usa spear-phishing, malware custom (es. CozyBear), e persistenza tramite task scheduler. Recenti report indicano che stanno prendendo di mira il settore energetico in Europa.",
        "actions": [
            "Verifica se ci sono email di phishing recenti nel sistema.",
            "Cerca altri IOC (Indicators of Compromise) noti di APT29.",
            "Fai un rapporto: attacco APT29, obiettivo spionaggio industriale."
        ],
        "next": {0: "step3_phish", 1: "end_partial", 2: "end_success"}
    },
    "step2_file_analysis": {
        "desc": "Il file energyschedule.exe è un dropper che installa un RAT (Remote Access Trojan). Il codice è simile a campioni attribuiti a APT29. Il file è stato scaricato da una email con mittente hr@company-energy.com (spoofed).",
        "actions": [
            "Analizza la email e il server di posta.",
            "Cerca altri host infetti nella rete.",
            "Fai un rapporto: attacco APT29, vettore phishing, obiettivo accesso remoto."
        ],
        "next": {0: "step3_phish", 1: "step4_other_hosts", 2: "end_success"}
    },
    "step3_phish": {
        "desc": "Trovata email con oggetto Nuovo piano energetico 2025 e allegato energy_plan_2025.docm. L’allegato contiene macro che scaricano il dropper. L’email è stata inviata a 5 dipendenti del reparto ingegneria.",
        "actions": [
            "Verifica se altri dipendenti hanno aperto l’allegato.",
            "Analizza il documento per trovare altri IOC.",
            "Fai un rapporto: campagna di phishing mirata, gruppo APT29, obiettivo spionaggio."
        ],
        "next": {0: "step4_other_users", 1: "end_partial", 2: "end_success"}
    },
    "step4_other_users": {
        "desc": "Altri 2 dipendenti hanno aperto l’allegato. Le loro workstation mostrano lo stesso traffico verso l’IP russo. Una workstation ha tentato di accedere a dati riservati sulla rete interna.",
        "actions": [
            "Isola tutte le workstation compromesse.",
            "Analizza i dati a cui hanno tentato di accedere.",
            "Fai un rapporto: attacco APT29 in corso, obiettivo esfiltrazione dati."
        ],
        "next": {0: "step5_win", 1: "step5_win", 2: "step5_win"}
    },
    "step5_win": {
        "desc": "L’agente ha identificato correttamente l’attacco APT29, il vettore (phishing), l’obiettivo (spionaggio industriale) e ha suggerito le azioni di contenimento. Partita vinta!",
        "actions": [],
        "next": {}
    },
    "end_success": {"desc": "Rapporto corretto. Minaccia identificata.", "actions": [], "next": {}},
    "end_partial": {"desc": "Risposta incompleta. Rischio residuo.", "actions": [], "next": {}},
    "end_fail": {"desc": "Rapporto prematuro. Attacco non rilevato.", "actions": [], "next": {}},
}



4. Funzione agent_choose_action
•	Scopo: L’agente (modello linguistico) sceglie l’azione migliore in base alla descrizione dello stato.
•	Funzionamento:
o	Costruisce un prompt che descrive la situazione e le azioni possibili.
o	Passa il prompt al modello, che genera una risposta (un numero tra 1, 2 o 3).
o	Estrae il numero dalla risposta e lo converte in indice dell’azione.
o	Se la risposta non è valida, torna l’indice 0 (fallback sicuro).

 

5. Motore di gioco automatico (play_game)
•	Scopo: Esegue una partita, simulando le scelte dell’agente fino a raggiungere uno stato terminale.
•	Logica:
o	Parte da step0.
o	Ad ogni passo, l’agente sceglie un’azione, si passa allo stato successivo, e si aggiorna la storia.
o	Se si raggiunge step5_win, la partita è vinta; altrimenti, si perde.
o	Il punteggio è inversamente proporzionale al numero di mosse (più veloce = punteggio più alto).
 


6. Esecuzione e Output
•	Scopo: Esegue una partita e stampa il risultato.
•	Output esempio:
🎮 RISULTATO PARTITA Stato: WIN
Mosse: 5
Punteggio: 5/10
🏆 Partita vinta! APT29 identificato correttamente.

 

RIEPILOGO E OBIETTIVO DEL CODICE
•	Obiettivo: Simulare il processo decisionale di un analista SOC di fronte a un attacco APT, usando un modello linguistico per scegliere le azioni migliori.
•	Meccanismo:
o	Catena di Markov per modellare le fasi dell’attacco.
o	Modello linguistico come "agente" che prende decisioni.
o	Valutazione dell’efficacia delle scelte (punteggio).
•	Applicazione pratica: Può essere usato per addestrare o testare la capacità di un modello di riconoscere e rispondere a minacce informatiche avanzate.

Ragionamento esplicito
# --------------------------------------------------------------------------------------------
# 1. Funzione: Agente con ragionamento esplicito (Chain-of-Thought)
# --------------------------------------------------------------------------------------------
def agent_choose_action_with_reasoning(state_desc: str, actions: list):
    if not actions:
        return -1, "Nessuna azione disponibile."

    options_text = "\n".join([f"{i+1}. {act}" for i, act in enumerate(actions)])
    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

Sei un analista SOC esperto. Dato un incidente in corso, devi:
1. Analizzare la situazione;
2. Valutare le opzioni;
3. Scegliere la MIGLIORE azione per identificare un attacco APT (es. APT29);
4. Spiegare il tuo ragionamento;
5. Concludere con: "Scelta: X" dove X è il numero dell'azione (1, 2 o 3).

Situazione:
{state_desc}

Azioni disponibili:
{options_text}
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    outputs = model.generate(
        **inputs,
        max_new_tokens=256,  # abbastanza per ragionamento + scelta
        temperature=0.3,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id,
    )
    full_response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    # Estrai solo la parte dopo l'ultimo <|start_header_id|>assistant<|end_header_id|>
    reasoning = full_response.split("<|start_header_id|>assistant<|end_header_id|>")[-1].strip()

    # Estrai la scelta finale
    import re
    choice_match = re.search(r"Scelta:\s*([123])", reasoning, re.IGNORECASE)
    if choice_match:
        idx = int(choice_match.group(1)) - 1
        if 0 <= idx < len(actions):
            return idx, reasoning
    # Fallback: cerca qualsiasi numero
    num_match = re.search(r"\b([123])\b", reasoning)
    if num_match:
        idx = int(num_match.group(1)) - 1
        if 0 <= idx < len(actions):
            return idx, reasoning
    return 0, reasoning + "\n⚠️ Scelta non chiara: fallback all'azione 1."

# ---------------------------------------------------------
# 2. Motore di gioco con output trasparente
# ---------------------------------------------------------
def play_game_transparent(max_steps=10):
    current = "step0"
    steps = 0
    history = []

    print("="*80)
    print("🕵️  SIMULAZIONE: Threat Hunting con APT29")
    print("Obiettivo: Identificare APT29, il vettore (phishing) e l'obiettivo (spionaggio) nel minor tempo possibile.")
    print("="*80)

    while steps < max_steps:
        state = states[current]
        history.append(state["desc"])

        print(f"\n🔹 STEP {steps}")
        print(f"📌 CONTESTO:\n{state['desc']}\n")

        if current == "step5_win":
            score = max(0, 10 - steps)
            print("🎉 RISULTATO: Partita vinta!")
            print(f"✅ Punteggio: {score}/10 ({steps} mosse)")
            return {"status": "win", "steps": steps, "score": score}

        if not state["actions"]:
            print(f"💀 TERMINALE NON VINCENTE: {current}")
            return {"status": "loss", "steps": steps, "score": 0, "terminal": current}

        print("🔍 AZIONI POSSIBILI:")
        for i, act in enumerate(state["actions"], 1):
            print(f"  {i}. {act}")

        # L'agente "pensa" e decide
        action_idx, reasoning = agent_choose_action_with_reasoning(state["desc"], state["actions"])
        chosen_action = state["actions"][action_idx]
        next_state = state["next"][action_idx]

        print("\n🧠 RAGIONAMENTO DELL'AGENTE:")
        print("-" * 50)
        print(reasoning)
        print("-" * 50)
        print(f"\n✅ AZIONE SCELTA: {chosen_action}")
        print(f"➡️  Prossimo stato: {next_state}")

        current = next_state
        steps += 1

    print("\n⏰ TIMEOUT: La partita non è stata completata in tempo.")
    return {"status": "loss", "steps": steps, "score": 0, "terminal": "timeout"}

# ---------------------------------------------------------
# 3. Avvia simulazione trasparente
# ---------------------------------------------------------
if __name__ == "__main__":
    result = play_game_transparent()



1. Funzione agent_choose_action_with_reasoning
•	Scopo: Questa funzione estende la versione precedente, chiedendo al modello linguistico non solo di scegliere un’azione, ma anche di spiegare il ragionamento dietro la scelta (Chain-of-Thought, CoT). Questo rende il processo decisionale trasparente e interpretabile.
•	Dettagli tecnici
def agent_choose_action_with_reasoning(state_desc: str, actions: list):
    if not actions:
        return -1, "Nessuna azione disponibile."
    options_text = "\n".join([f"{i+1}. {act}" for i, act in enumerate(actions)])
    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
    Sei un analista SOC esperto. Dato un incidente in corso, devi:
    1. Analizzare la situazione;
    2. Valutare le opzioni;
    3. Scegliere la MIGLIORE azione per identificare un attacco APT (es. APT29);
    4. Spiegare il tuo ragionamento;
    5. Concludere con: "Scelta: X" dove X è il numero dell'azione (1, 2 o 3).
    Situazione:
    {state_desc}
    Azioni disponibili:
    {options_text}
    <|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

•	Prompt strutturato: Il prompt guida il modello a seguire un processo logico in 5 passaggi, chiedendo esplicitamente una spiegazione del ragionamento e una scelta finale formattata come "Scelta: X".
•	Generazione della risposta:
outputs = model.generate(
    **inputs,
    max_new_tokens=256,  # abbastanza per ragionamento + scelta
    temperature=0.3,
    do_sample=True,
    pad_token_id=tokenizer.eos_token_id,
)
•	max_new_tokens=256: Permette al modello di generare una risposta dettagliata, non solo un numero.
•	temperature=0.3: Mantiene una certa variabilità, ma con una buona coerenza.

Estrazione della scelta e del ragionamento:
full_response = tokenizer.decode(outputs[0], skip_special_tokens=True)
reasoning = full_response.split("<|start_header_id|>assistant<|end_header_id|>")[-1].strip()
choice_match = re.search(r"Scelta:\s*([123])", reasoning, re.IGNORECASE)
•	Estrae il testo generato dal modello.
•	Cerca la stringa "Scelta: X" per determinare l’azione scelta.
•	Se non trova "Scelta: X", cerca un numero tra 1, 2 o 3 nel testo.
•	Fallback: Se non riesce a estrarre una scelta valida, torna l’indice 0 e aggiunge un avviso.



2. Motore di gioco trasparente (play_game_transparent)
•	Scopo: Questa funzione esegue la simulazione, ma stampa a video ogni passo, mostrando il contesto, le azioni possibili, il ragionamento dell’agente e la scelta finale. Questo rende il processo completamente trasparente e comprensibile all’utente.
def play_game_transparent(max_steps=10):
    current = "step0"
    steps = 0
    history = []
    print("="*80)
    print("🕵️  SIMULAZIONE: Threat Hunting con APT29")
    print("Obiettivo: Identificare APT29, il vettore (phishing) e l'obiettivo (spionaggio) nel minor tempo possibile.")
    print("="*80)

•	Stampa iniziale: Spiega lo scopo della simulazione.
while steps < max_steps:
    state = states[current]
    history.append(state["desc"])
    print(f"\n🔹 STEP {steps}")
    print(f"📌 CONTESTO:\n{state['desc']}\n")
    if current == "step5_win":
        score = max(0, 10 - steps)
        print("🎉 RISULTATO: Partita vinta!")
        print(f"✅ Punteggio: {score}/10 ({steps} mosse)")
        return {"status": "win", "steps": steps, "score": score}
    if not state["actions"]:
        print(f"💀 TERMINALE NON VINCENTE: {current}")
        return {"status": "loss", "steps": steps, "score": 0, "terminal": current}
    print("🔍 AZIONI POSSIBILI:")
    for i, act in enumerate(state["actions"], 1):
        print(f"  {i}. {act}")

•	Stampa del contesto e delle azioni: Mostra all’utente la situazione attuale e le opzioni disponibili.
action_idx, reasoning = agent_choose_action_with_reasoning(state["desc"], state["actions"])
chosen_action = state["actions"][action_idx]
next_state = state["next"][action_idx]
print("\n🧠 RAGIONAMENTO DELL'AGENTE:")
print("-" * 50)
print(reasoning)
print("-" * 50)
print(f"\n✅ AZIONE SCELTA: {chosen_action}")
print(f"➡️  Prossimo stato: {next_state}")
current = next_state
steps += 1



•	Stampa del ragionamento e della scelta: Mostra il processo decisionale dell’agente, l’azione scelta e il prossimo stato.
print("\n⏰ TIMEOUT: La partita non è stata completata in tempo.")
return {"status": "loss", "steps": steps, "score": 0, "terminal": "timeout"}
•	Timeout: Se il numero massimo di passi viene raggiunto, la partita termina con un timeout.



3. Esecuzione della simulazione
if __name__ == "__main__":
    result = play_game_transparent()
Avvia la simulazione trasparente, mostrando tutti i passaggi e il ragionamento dell’agente.



--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


Considerazioni sul codice

TEMPERATURE
Analizzando e modificando il codice, uno dei fattori più importanti relativo al modo in cui le risposte vengono fornite e gestite è il parametro Temperature. Temperaturaùe regola la distribuzione di probabilità dei token (parole o parti di parole) durante la generazione del testo, determinando quanto il modello sia "creativo" o "prevedibile" nelle sue risposte. Più il valore associato a tale parametro è vicino allo 0, più la risposta fornita risulta coerente e precisa, ma anche più prevedibile e poco creativa. Per valori che si avvicinano ad 1.0, le risposte risultano più creative ed originali, ma anche più casuali e con un maggior rischio di errori, incoerenze e possono risultare anche fuori contesto.
Poiché i modelli che si basano su catene di Markov (o più in generale, su processi stocastici) traggono vantaggio da una certa casualità per esplorare diverse possibilità, ho pensato inizialmente di utilizzare un valore di Temperature che si aggirasse sullo 0.6, garantendo una certa precisione alle risposte fornite, ma al contempo fornendo anche una certa libertà nella scelta di tali risposte. Tuttavia, testando il programma, tale valore non è risultato idoneo per lo scopo dell’A.I. sviluppata, la quale necessita di risposte abbastanza standard, pur dovendo avere un margine di libertà di ragionamento. Il valore che si è dimostrato più corretto è stato 0.3, in quanto, attraverso tale valore, le risposte risultavano coincise e precise, ma si lascia allo stesso tempo anche un certo margine di libertà al programma nella scelta delle sue risposte.

N° DI TOKEN MASSIMI
La scelta relativa al numero di token massimi è stata presa sulla base del tipo di risposte che volevo ottenere, ovvero risposte non troppo lunghe, ma che fornissero una giustificazione adeguate delle scelte prese. 
Ad un numero di token troppo bassi corrispondevano risposte sintetiche, ma troppo brevi, che non spiegavano in maniera accettabile le decisioni prese dall’A.I. e che portavano spesso a fallback.
Ad un numero di token troppo alti corrispondevano invece risposte troppo lunghe e prolisse, cosa che per il tipo di programma sviluppato non risultava idoneo, con risposte spesso ripetitive. 
Il numero massimo di token che è risultato corretto per determinare il tipo di risposte desiderate è stato 256.

PROMPT
Le scelte relative ad il prompt utilizzato vertono su una descrizione semplice e facilmente comprensibile di ciò che il programma deve fare per poter emulare correttamente il comportamento di un analista SOC. La struttura utilizzata è pertanto semplice e chiara, facilmente modificabile, per essere adattata anche a contesti diversi da  quelli per cui è stata originariamente pensata, e spiega le scelte fatte in modo semplice e chiaro. 
Il tipo di sistema scelto per lo sviluppo dell’A.I. considerata è noto come sistema di Apprendimento per Rinforzo (Reinforcement Learning). Le intelligenze artificiali che si basano su un sistema di questo tipo prevedono scelte guidate da punteggi (scoring o reward) assegnati in base alla qualità o all’appropriatezza delle soluzioni trovate.
Questo tipo di approccio porta a diversi benefici, tra cui la capacità di trovare soluzioni ottimali o quasi-ottimali in contesti complessi (Ottimizzazione) e la possibilità di tarare il sistema di punteggio su obiettivi specifici, rendendo l’A.I. più efficace in contesti particolari (Personalizzazione).


