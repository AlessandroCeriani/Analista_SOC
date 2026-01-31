# ---------------------------------------------------------
# 1. Funzione: Agente con ragionamento esplicito (Chain-of-Thought)
# ---------------------------------------------------------
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