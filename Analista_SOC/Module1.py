# Scopo: Installa le librerie necessarie per caricare e usare un modello linguistico ottimizzato 
# (Unsloth) e per la gestione di modelli di trasformatori (Hugging Face).

%%capture
import os, re
if "COLAB_" not in "".join(os.environ.keys()):
    !pip install unsloth
else:
    import torch
    v = re.match(r"[0-9\.]{3,}", str(torch.__version__)).group(0)
    xformers = "xformers==" + ("0.0.32.post2" if v == "2.8.0" else "0.0.29.post3")
    !pip install --no-deps bitsandbytes accelerate {xformers} peft trl triton cut_cross_entropy unsloth_zoo
    !pip install sentencepiece protobuf "datasets>=3.4.1,<4.0.0" "huggingface_hub>=0.34.0" hf_transfer
    !pip install --no-deps unsloth
!pip install transformers==4.56.2
!pip install --no-deps trl==0.22.2





# Scopo: Carica un modello linguistico pre-addestrato (Llama-3.2-3B) in modalità inferenza, 
# ottimizzato per l’uso di memoria (4 bit).

from unsloth import FastLanguageModel
import torch

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "unsloth/Llama-3.2-3B-Instruct-bnb-4bit",
    max_seq_length = 2048,
    dtype = None,
    load_in_4bit = True,
)

%%capture
# 1. Pulizia e preparazione ambiente
import os
if "COLAB_" in "".join(os.environ.keys()):
    # Disinstalla eventuali versioni conflittuali
    !pip uninstall -y unsloth transformers trl peft bitsandbytes accelerate xformers
    # Installa solo unsloth (che gestisce automaticamente le dipendenze corrette)
    !pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
    # Riavvia la runtime dopo questa cella (su Colab: Runtime > Restart runtime)
else:
    # Per ambienti non-Colab (locale, Kaggle, etc.)
    !pip install unsloth

# 2. Dopo il riavvio, esegui solo da qui in poi
from unsloth import FastLanguageModel
import torch

# 3. Caricamento modello
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/Llama-3.2-3B-Instruct-bnb-4bit",
    max_seq_length=2048,
    dtype=None,
    load_in_4bit=True,
)

print("Modello caricato con successo!")





# Scopo: Definisce uno spazio di stati che rappresentano le fasi di un attacco APT e 
# le possibili azioni dell’analista.

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





# Scopo: L’agente (modello linguistico) sceglie l’azione migliore in base alla descrizione dello stato.

def agent_choose_action(state_desc: str, actions: list) -> int:
    if not actions:
        return -1

    options_text = "\n".join([f"{i+1}. {act}" for i, act in enumerate(actions)])
    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
Sei un analista SOC esperto. Data la situazione e le azioni possibili, scegli la MIGLIORE opzione per identificare un attacco APT.
Rispondi SOLO con il numero dell'azione (es. 1, 2 o 3).

Situazione:
{state_desc}

Azioni:
{options_text}
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    outputs = model.generate(
        **inputs,
        max_new_tokens=5,
        temperature=0.3,  # leggermente stocastico per evitare loop
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id,
    )
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    import re
    match = re.search(r'\b([123])\b', response)
    if match:
        idx = int(match.group(1)) - 1
        if 0 <= idx < len(actions):
            return idx
    return 0  # fallback sicuro





# Scopo: Esegue una partita, simulando le scelte dell’agente fino a raggiungere uno stato terminale.

def play_game(max_steps=10):
    current = "step0"
    steps = 0
    history = []

    while steps < max_steps:
        state = states[current]
        history.append(state["desc"])

        if current == "step5_win":
            score = max(0, 10 - steps)
            return {"status": "win", "steps": steps, "score": score, "history": history}

        if not state["actions"]:
            # Terminale non vincente
            return {"status": "loss", "steps": steps, "score": 0, "history": history, "reason": current}

        # Agente sceglie
        action_idx = agent_choose_action(state["desc"], state["actions"])
        chosen_action = state["actions"][action_idx]
        next_state = state["next"][action_idx]

        # Debug opzionale
        # print(f"[Step {steps}] Scelto: {chosen_action[:50]}... -> {next_state}")

        current = next_state
        steps += 1

    return {"status": "loss", "steps": steps, "score": 0, "history": history, "reason": "timeout"}





# Scopo: Esegue una partita e stampa il risultato.

if __name__ == "__main__":
    result = play_game()
    print("\n" + "="*60)
    print(f"🎮 RISULTATO PARTITA")
    print(f"Stato: {result['status'].upper()}")
    print(f"Mosse: {result['steps']}")
    print(f"Punteggio: {result['score']}/10")
    if result["status"] == "win":
        print("🏆 Partita vinta! APT29 identificato correttamente.")
    else:
        print(f"❌ Persa: {result.get('reason', 'sconosciuto')}")