#----------------------------------------------------------------------------------
#                                   ATTENZIONE
#----------------------------------------------------------------------------------
# Il seguente codice è stato sviluppato per essere eseguito e testato nell'ambiente 
# di lavoro Google Colaboratory, pertanto, se si desidera eseguire il codice 
# su un qualsiasi dispositivo senza avvalersi di tale piattaforma, il codice 
# dovrà essere modificato adeguatamente per funzionare in maniera corretta.
#----------------------------------------------------------------------------------


# 1) Installazione delle librerie
!pip install unsloth
!pip install transformers torch
!pip install -q transformers accelerate sentencepiece




# 2) Importazione di librerie, moduli e pacchetti
import json
from typing import Dict, List, Tuple, Optional, Callable
import torch

try:
    from unsloth import FastLanguageModel
    UNSLOTH_AVAILABLE = True
except ImportError:
    print("⚠️ La libreria 'unsloth' non è disponibile. Usato un agente di fallback.")
    UNSLOTH_AVAILABLE = False

from transformers import AutoTokenizer





# 3) Scenari d'attacco

# --- SCENARI INTEGRATI ---
scenarios = {
    "apt29": {
        "name": "Simulazione Attacco APT29",
        "optimal_steps": 4,
        "description": "Obiettivo: Identificare APT29, il vettore (phishing) e l'obiettivo (spionaggio) nel minor tempo possibile.",
        "states": {
            "step0": {
                "desc": "Rilevato traffico anomalo verso un IP in Russia (185.143.223.42) dalle workstation del reparto ingegneria. Nessun allarme dai sistemi antivirus, ma il traffico è cifrato e persistente da 3 giorni.",
                "actions": [
                    {
                        "action": "Richiedi dettagli sull’IP e sul tipo di traffico.",
                        "cvss": {
                            "score": 4.3,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Basso rischio immediato, ma necessaria indagine per identificare la minaccia."
                        }
                    },
                    {
                        "action": "Esegui una scansione approfondita sulle workstation coinvolte.",
                        "cvss": {
                            "score": 6.8,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            "impact": "Rischio di esposizione di dati sensibili e compromissione dell’integrità dei sistemi."
                        }
                    },
                    {
                        "action": "Fai un rapporto: sospetto attacco APT in corso.",
                        "cvss": {
                            "score": 3.5,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta e falsi positivi."
                        }
                    }
                ],
                "next": {0: "step1_ip", 1: "step1_scan", 2: "end_fail"}
            },
            "step1_ip": {
                "desc": "L’IP 185.143.223.42 è associato a un server C2 noto, precedentemente utilizzato dal gruppo APT29 (Cozy Bear). Il traffico è compatibile con il protocollo di comando e controllo di malware custom.",
                "actions": [
                    {
                        "action": "Richiedi informazioni su APT29 e le loro TTP (Tactics, Techniques, Procedures).",
                        "cvss": {
                            "score": 5.5,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Rischio di esposizione di informazioni sensibili sulle TTP, ma necessario per la difesa."
                        }
                    },
                    {
                        "action": "Analizza i log delle workstation per trovare file sospetti.",
                        "cvss": {
                            "score": 7.5,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            "impact": "Alto rischio di scoperta di malware attivo e compromissione dei dati."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco APT29 confermato.",
                        "cvss": {
                            "score": 4.0,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Conferma dell’attacco, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step2_ttp", 1: "step2_logs", 2: "end_success"}
            },
            "step1_scan": {
                "desc": "Trovato un file sospetto: energyschedule.exe (firmato digitalmente, ma con hash sconosciuto). Il file comunica con l’IP russo e ha creato una backdoor.",
                "actions": [
                    {
                        "action": "Richiedi analisi statica e dinamica del file.",
                        "cvss": {
                            "score": 8.8,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "impact": "Analisi di un malware attivo, alto rischio di compromissione del sistema di analisi."
                        }
                    },
                    {
                        "action": "Isola le workstation e blocca il traffico verso l’IP.",
                        "cvss": {
                            "score": 6.5,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Riduzione della disponibilità dei sistemi, ma contenimento della minaccia."
                        }
                    },
                    {
                        "action": "Fai un rapporto: malware custom, probabilmente APT.",
                        "cvss": {
                            "score": 4.7,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step2_file_analysis", 1: "end_partial", 2: "end_success"}
            },
            "step2_ttp": {
                "desc": "APT29 usa spear-phishing, malware custom (es. CozyBear), e persistenza tramite task scheduler. Recenti report indicano che stanno prendendo di mira il settore energetico in Europa.",
                "actions": [
                    {
                        "action": "Verifica se ci sono email di phishing recenti nel sistema.",
                        "cvss": {
                            "score": 6.1,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Rischio di esposizione di credenziali e dati sensibili tramite phishing."
                        }
                    },
                    {
                        "action": "Cerca altri IOC (Indicators of Compromise) noti di APT29.",
                        "cvss": {
                            "score": 5.8,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Possibile scoperta di ulteriori compromissioni, ma rischio di falsi positivi."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco APT29, obiettivo spionaggio industriale.",
                        "cvss": {
                            "score": 4.2,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step3_phish", 1: "end_partial", 2: "end_success"}
            },
            "step2_file_analysis": {
                "desc": "Il file energyschedule.exe è un dropper che installa un RAT (Remote Access Trojan). Il codice è simile a campioni attribuiti a APT29. Il file è stato scaricato da una email con mittente hr@company-energy.com (spoofed).",
                "actions": [
                    {
                        "action": "Analizza la email e il server di posta.",
                        "cvss": {
                            "score": 7.2,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            "impact": "Rischio di compromissione del server di posta e esposizione di credenziali."
                        }
                    },
                    {
                        "action": "Cerca altri host infetti nella rete.",
                        "cvss": {
                            "score": 6.9,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
                            "impact": "Rischio di scoperta di infezioni multiple e lateral movement."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco APT29, vettore phishing, obiettivo accesso remoto.",
                        "cvss": {
                            "score": 4.5,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step3_phish", 1: "step4_other_hosts", 2: "end_success"}
            },
            "step2_logs": {
                "desc": "Nei log sono stati trovati accessi anomali a file sensibili e connessioni a orari insoliti. Alcuni file sono stati compressi e inviati all’IP russo.",
                "actions": [
                    {
                        "action": "Analizza i file compressi per capire cosa è stato esfiltrato.",
                        "cvss": {
                            "score": 8.1,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            "impact": "Rischio di esposizione di dati sensibili già esfiltrati."
                        }
                    },
                    {
                        "action": "Verifica se ci sono altri IP di destinazione.",
                        "cvss": {
                            "score": 6.3,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Possibile scoperta di ulteriori canali di esfiltrazione."
                        }
                    },
                    {
                        "action": "Fai un rapporto: esfiltrazione dati in corso, gruppo APT29.",
                        "cvss": {
                            "score": 4.8,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step3_exfiltration", 1: "step4_other_ips", 2: "end_success"}
            },
            "step3_phish": {
                "desc": "Trovata email con oggetto 'Nuovo piano energetico 2025' e allegato energy_plan_2025.docm. L’allegato contiene macro che scaricano il dropper. L’email è stata inviata a 5 dipendenti del reparto ingegneria.",
                "actions": [
                    {
                        "action": "Verifica se altri dipendenti hanno aperto l’allegato.",
                        "cvss": {
                            "score": 7.0,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Rischio di scoperta di ulteriori infezioni e compromissioni."
                        }
                    },
                    {
                        "action": "Analizza il documento per trovare altri IOC.",
                        "cvss": {
                            "score": 6.5,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Possibile scoperta di ulteriori indicatori di compromissione."
                        }
                    },
                    {
                        "action": "Fai un rapporto: campagna di phishing mirata, gruppo APT29, obiettivo spionaggio.",
                        "cvss": {
                            "score": 4.3,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step4_other_users", 1: "end_partial", 2: "end_success"}
            },
            "step3_exfiltration": {
                "desc": "I file compressi contengono documenti riservati sul progetto 'Energia Verde 2030'. Sono stati inviati 3GB di dati all’IP russo negli ultimi 2 giorni.",
                "actions": [
                    {
                        "action": "Blocca immediatamente l’esfiltrazione e isola i sistemi compromessi.",
                        "cvss": {
                            "score": 8.5,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            "impact": "Contenimento urgente, ma rischio di interruzione dei servizi."
                        }
                    },
                    {
                        "action": "Verifica se i dati sono stati crittografati prima dell’invio.",
                        "cvss": {
                            "score": 6.0,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Possibile scoperta di ulteriori dettagli sulla compromissione."
                        }
                    },
                    {
                        "action": "Fai un rapporto: esfiltrazione massiva, gruppo APT29, obiettivo furto proprietà intellettuale.",
                        "cvss": {
                            "score": 4.6,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step4_containment", 1: "end_partial", 2: "end_success"}
            },
            "step4_other_users": {
                "desc": "Altri 2 dipendenti hanno aperto l’allegato. Le loro workstation mostrano lo stesso traffico verso l’IP russo. Una workstation ha tentato di accedere a dati riservati sulla rete interna.",
                "actions": [
                    {
                        "action": "Isola tutte le workstation compromesse.",
                        "cvss": {
                            "score": 7.8,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Contenimento urgente, ma riduzione della disponibilità."
                        }
                    },
                    {
                        "action": "Analizza i dati a cui hanno tentato di accedere.",
                        "cvss": {
                            "score": 6.7,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "impact": "Possibile scoperta di ulteriori dati compromessi."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco APT29 in corso, obiettivo esfiltrazione dati.",
                        "cvss": {
                            "score": 4.4,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step5_win", 1: "step5_win", 2: "step5_win"}
            },
            "step4_other_hosts": {
                "desc": "Trovati altri 3 host infetti nella rete, tutti nel reparto ingegneria. Stanno comunicando con lo stesso IP russo e hanno file sospetti simili.",
                "actions": [
                    {
                        "action": "Isola tutti gli host infetti e blocca il traffico verso l’IP russo.",
                        "cvss": {
                            "score": 8.2,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Contenimento urgente, ma riduzione della disponibilità."
                        }
                    },
                    {
                        "action": "Analizza la lateral movement all’interno della rete.",
                        "cvss": {
                            "score": 7.3,
                            "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            "impact": "Possibile scoperta di ulteriori compromissioni."
                        }
                    },
                    {
                        "action": "Fai un rapporto: infezione diffusa, gruppo APT29, obiettivo controllo rete.",
                        "cvss": {
                            "score": 4.5,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "impact": "Segnalazione utile, ma senza azioni di contenimento immediate."
                        }
                    }
                ],
                "next": {0: "step5_win", 1: "step5_win", 2: "step5_win"}
            },
            "step4_containment": {
                "desc": "L’esfiltrazione è stata bloccata e i sistemi compromessi sono stati isolati. I dati esfiltrati sono stati identificati e segnalati al team legale.",
                "actions": [],
                "next": {"desc": "Partita vinta: attacco APT29 identificato e contenuto con successo!", "next": {}}
            },
            "step5_win": {
                "desc": "L’agente ha identificato correttamente l’attacco APT29, il vettore (phishing), l’obiettivo (spionaggio industriale) e ha suggerito le azioni di contenimento. Partita vinta!",
                "actions": [],
                "next": {}
            },
            "end_success": {"desc": "Rapporto corretto. Minaccia identificata.", "actions": [], "next": {}},
            "end_partial": {"desc": "Risposta incompleta. Rischio residuo.", "actions": [], "next": {}},
            "end_fail": {"desc": "Rapporto prematuro. Attacco non rilevato.", "actions": [], "next": {}}
        }
    },
    "ddos": {
        "name": "Simulazione Attacco DDoS",
        "optimal_steps": 6,
        "description": "Obiettivo: Mitigare un attacco DDoS e ripristinare la disponibilità del servizio.",
        "states": {
            "step0": {
                "desc": "Il sistema di monitoraggio segnalano un improvviso picco di traffico verso il sito web principale (shop.example.com). La banda passante è al 95%, i server rispondono con latenza elevata (5+ secondi). Nessun allarme dai firewall, ma il traffico proviene da migliaia di IP diversi.",
                "actions": [
                    {
                        "action": "Verifica lo stato dei server web e database.",
                        "cvss": {
                            "score": 5.3,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Rischio di indisponibilità del servizio, ma necessaria per la diagnosi."
                        }
                    },
                    {
                        "action": "Analizza la provenienza geografica del traffico anomalo.",
                        "cvss": {
                            "score": 4.7,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Informazioni utili per il blocco geografico, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: possibile attacco DDoS in corso.",
                        "cvss": {
                            "score": 3.5,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step1_servers", 1: "step1_geo", 2: "end_fail"}
            },
            "step1_servers": {
                "desc": "I server web sono sotto carico elevato (CPU 90%, RAM 85%). Il database risponde con errori di timeout. Le richieste HTTP sono principalmente GET su pagine prodotto e checkout, ma con una frequenza anomala (10.000 RPS).",
                "actions": [
                    {
                        "action": "Attiva il rate limiting sulle pagine critiche.",
                        "cvss": {
                            "score": 6.2,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Riduzione del carico, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Verifica se il traffico è legittimo (es. bot di scraping, crawler).",
                        "cvss": {
                            "score": 4.9,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione di falsi positivi, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco volumetrico, obiettivo saturazione risorse.",
                        "cvss": {
                            "score": 3.8,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step2_rate_limit", 1: "step2_bot_check", 2: "end_partial"}
            },
            "step1_geo": {
                "desc": "Il traffico anomalo proviene principalmente da IP in Cina, Russia e Brasile. Gli IP sono distribuiti su diverse reti e non appartengono a provider noti. Alcuni IP sono già segnalati in blacklist pubbliche per attività malevole.",
                "actions": [
                    {
                        "action": "Blocca temporaneamente il traffico dalle regioni sospette.",
                        "cvss": {
                            "score": 5.9,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Riduzione del traffico malevolo, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Analizza i pattern delle richieste per identificare il tipo di attacco (SYN flood, HTTP flood, etc.).",
                        "cvss": {
                            "score": 5.5,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione del tipo di attacco, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS distribuito, origine geografica sospetta.",
                        "cvss": {
                            "score": 3.7,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step2_block_geo", 1: "step2_pattern", 2: "end_partial"}
            },
            "step2_rate_limit": {
                "desc": "Il rate limiting ha ridotto il carico, ma il sito è ancora lento. Le richieste continuano a provenire da nuovi IP. Alcune richieste contengono header HTTP insoliti (es. User-Agent vuoto o randomizzato).",
                "actions": [
                    {
                        "action": "Configura regole WAF per bloccare header sospetti.",
                        "cvss": {
                            "score": 6.7,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Blocco di traffico malevolo, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Analizza i log per identificare pattern di attacco (es. richieste identiche, payload malformati).",
                        "cvss": {
                            "score": 5.8,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione di pattern di attacco, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco HTTP flood, necessarie contromisure avanzate.",
                        "cvss": {
                            "score": 4.0,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step3_waf", 1: "step3_logs", 2: "end_partial"}
            },
            "step2_block_geo": {
                "desc": "Il blocco geografico ha ridotto il traffico del 40%, ma l’attacco continua da altre regioni. Alcune richieste sembrano legittime, ma provengono da proxy o VPN.",
                "actions": [
                    {
                        "action": "Implementa CAPTCHA sulle pagine critiche.",
                        "cvss": {
                            "score": 6.3,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H",
                            "impact": "Blocco di traffico automatizzato, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Verifica se l’attacco sta usando tecniche di IP spoofing.",
                        "cvss": {
                            "score": 5.7,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione di tecniche di evasione, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS con evasione geografica, necessarie contromisure dinamiche.",
                        "cvss": {
                            "score": 3.9,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step3_captcha", 1: "step3_spoofing", 2: "end_partial"}
            },
            "step2_pattern": {
                "desc": "Le richieste seguono uno schema: 80% GET su /product?id=12345, 20% POST su /checkout con payload vuoto. Il pattern è compatibile con un attacco HTTP flood automatizzato.",
                "actions": [
                    {
                        "action": "Crea regole di mitigazione specifiche per questi endpoint.",
                        "cvss": {
                            "score": 7.1,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Blocco di traffico malevolo, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Verifica se l’attacco sta sfruttando vulnerabilità note (es. Slowloris).",
                        "cvss": {
                            "score": 6.4,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione di vulnerabilità sfruttate, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco HTTP flood mirato, obiettivo disservizio checkout.",
                        "cvss": {
                            "score": 4.1,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step3_mitigation", 1: "step3_vuln", 2: "end_partial"}
            },
            "step3_waf": {
                "desc": "Le regole WAF hanno bloccato il 60% del traffico malevolo. Tuttavia, l’attacco si sta adattando: ora le richieste includono header legittimi e payload variabili.",
                "actions": [
                    {
                        "action": "Attiva la modalità ‘challenge’ per tutte le richieste sospette.",
                        "cvss": {
                            "score": 7.4,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H",
                            "impact": "Blocco di traffico malevolo, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Contatta il provider di hosting per attivare protezioni DDoS a livello di rete.",
                        "cvss": {
                            "score": 6.9,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Mitigazione efficace, ma dipendenza da terze parti."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS evoluto, necessaria collaborazione con provider esterni.",
                        "cvss": {
                            "score": 4.2,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step4_challenge", 1: "step4_provider", 2: "end_partial"}
            },
            "step3_captcha": {
                "desc": "Il CAPTCHA ha ridotto il traffico automatizzato, ma gli utenti legittimi segnalano difficoltà nell’accesso. L’attacco continua con richieste a bassa frequenza ma costanti.",
                "actions": [
                    {
                        "action": "Monitora l’impatto sugli utenti legittimi e regola la soglia del CAPTCHA.",
                        "cvss": {
                            "score": 5.6,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Ottimizzazione delle contromisure, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Analizza se l’attacco sta usando bot avanzati in grado di risolvere CAPTCHA.",
                        "cvss": {
                            "score": 6.1,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione di bot avanzati, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS persistente, necessaria ottimizzazione delle contromisure.",
                        "cvss": {
                            "score": 3.8,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step4_monitor", 1: "step4_bot_analysis", 2: "end_partial"}
            },
            "step3_mitigation": {
                "desc": "Le regole di mitigazione hanno ridotto il carico, ma l’attacco si è spostato su altri endpoint (es. /api/inventory). Il traffico ora include richieste con parametri randomizzati per eludere le regole.",
                "actions": [
                    {
                        "action": "Estendi le regole di mitigazione a tutti gli endpoint critici.",
                        "cvss": {
                            "score": 7.2,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                            "impact": "Blocco di traffico malevolo, ma possibile impatto su utenti legittimi."
                        }
                    },
                    {
                        "action": "Verifica se l’attacco sta usando tecniche di ‘low and slow’ per evitare il rilevamento.",
                        "cvss": {
                            "score": 6.5,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione di tecniche di evasione, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS adattivo, necessaria strategia di difesa dinamica.",
                        "cvss": {
                            "score": 4.0,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step4_extend_rules", 1: "step4_low_slow", 2: "end_partial"}
            },
            "step4_challenge": {
                "desc": "La modalità ‘challenge’ ha bloccato la maggior parte del traffico malevolo. Tuttavia, alcuni utenti legittimi segnalano ritardi. L’attacco sembra essersi ridotto, ma potrebbe riprendere.",
                "actions": [
                    {
                        "action": "Monitora il traffico per rilevare eventuali nuove ondate di attacco.",
                        "cvss": {
                            "score": 5.2,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Monitoraggio proattivo, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Prepara un piano di rollback per disattivare le contromisure in caso di falsi positivi.",
                        "cvss": {
                            "score": 4.8,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Prevenzione di impatti su utenti legittimi, ma possibile ripresa dell’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS mitigato, necessaria fase di monitoraggio attivo.",
                        "cvss": {
                            "score": 3.6,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step5_monitor", 1: "step5_rollback", 2: "end_success"}
            },
            "step4_provider": {
                "desc": "Il provider ha attivato la protezione DDoS a livello di rete. Il traffico malevolo è ora filtrato prima di raggiungere i server. Il sito è tornato accessibile, ma con latenza residua.",
                "actions": [
                    {
                        "action": "Collabora con il provider per ottimizzare le regole di filtraggio.",
                        "cvss": {
                            "score": 6.0,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Ottimizzazione delle contromisure, ma dipendenza da terze parti."
                        }
                    },
                    {
                        "action": "Analizza i log per identificare l’origine dell’attacco e possibili motivazioni.",
                        "cvss": {
                            "score": 5.4,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione degli autori, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS mitigato grazie al provider, necessaria analisi post-attacco.",
                        "cvss": {
                            "score": 3.7,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step5_optimize", 1: "step5_analysis", 2: "end_success"}
            },
            "step5_monitor": {
                "desc": "Dopo 2 ore di monitoraggio, non si rilevano nuove ondate di attacco. Il traffico è tornato nella norma. Alcuni utenti segnalano ancora errori sporadici.",
                "actions": [
                    {
                        "action": "Verifica la presenza di bot residui o attività sospette.",
                        "cvss": {
                            "score": 5.0,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile identificazione di attività residue, ma non risolve l’attacco."
                        }
                    },
                    {
                        "action": "Prepara un report dettagliato sull’attacco per il team di sicurezza.",
                        "cvss": {
                            "score": 3.5,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma utile per la documentazione."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS concluso, necessaria analisi post-incidente.",
                        "cvss": {
                            "score": 3.2,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step6_bot_check", 1: "step6_report", 2: "end_success"}
            },
            "step5_rollback": {
                "desc": "Le contromisure sono state disattivate per ridurre i falsi positivi. Il sito è ora pienamente accessibile, ma il rischio di un nuovo attacco persiste.",
                "actions": [
                    {
                        "action": "Mantieni un monitoraggio costante del traffico.",
                        "cvss": {
                            "score": 4.5,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Monitoraggio proattivo, ma non risolve il rischio residuo."
                        }
                    },
                    {
                        "action": "Prepara un piano di risposta rapida in caso di recidiva.",
                        "cvss": {
                            "score": 4.0,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Prevenzione di futuri attacchi, ma non risolve il rischio immediato."
                        }
                    },
                    {
                        "action": "Fai un rapporto: contromisure disattivate, necessaria vigilanza costante.",
                        "cvss": {
                            "score": 3.0,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma possibile ritardo nella risposta."
                        }
                    }
                ],
                "next": {0: "step6_monitor", 1: "step6_plan", 2: "end_success"}
            },
            "step6_bot_check": {
                "desc": "Non si rilevano bot residui. Tuttavia, alcuni IP sospetti continuano a scansionare la rete. Potrebbe trattarsi di ricognizione per futuri attacchi.",
                "actions": [
                    {
                        "action": "Blocca gli IP sospetti e aggiorna le blacklist.",
                        "cvss": {
                            "score": 5.5,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Prevenzione di futuri attacchi, ma non risolve il rischio immediato."
                        }
                    },
                    {
                        "action": "Valuta l’implementazione di un sistema di rilevamento anomalie basato su AI.",
                        "cvss": {
                            "score": 5.0,
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Miglioramento delle difese future, ma non risolve il rischio immediato."
                        }
                    },
                    {
                        "action": "Fai un rapporto: attacco DDoS terminato, ma rischio di futuri attacchi persiste.",
                        "cvss": {
                            "score": 3.3,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma utile per la documentazione."
                        }
                    }
                ],
                "next": {0: "step7_block", 1: "step7_ai", 2: "end_success"}
            },
            "step6_report": {
                "desc": "Il report dettagliato è stato preparato: l’attacco ha avuto una durata di 3 ore, con picchi di 15.000 RPS. L’obiettivo era probabilmente il disservizio durante il Black Friday.",
                "actions": [
                    {
                        "action": "Condividi il report con il team di sicurezza e la direzione.",
                        "cvss": {
                            "score": 3.0,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma utile per la condivisione delle informazioni."
                        }
                    },
                    {
                        "action": "Valuta l’opportunità di denunciare l’attacco alle autorità competenti.",
                        "cvss": {
                            "score": 3.5,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Possibile azione legale, ma non risolve il rischio immediato."
                        }
                    },
                    {
                        "action": "Fai un rapporto: analisi post-incidente completata, necessarie azioni legali e preventive.",
                        "cvss": {
                            "score": 3.1,
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "impact": "Nessun impatto diretto, ma utile per la documentazione."
                        }
                    }
                ],
                "next": {0: "step7_share", 1: "step7_legal", 2: "end_success"}
            },
            "step7_block": {
                "desc": "Gli IP sospetti sono stati bloccati. Il sistema di monitoraggio è stato potenziato per rilevare attività di ricognizione. Il rischio di futuri attacchi è stato ridotto.",
                "actions": [],
                "next": {"desc": "Partita vinta: attacco DDoS gestito con successo, contromisure efficaci e sistema protetto per il futuro.", "next": {}}
            },
            "step7_ai": {
                "desc": "È stato avviato un progetto pilota per implementare un sistema di rilevamento anomalie basato su AI. Il sistema sarà addestrato sui pattern dell’attacco appena subito.",
                "actions": [],
                "next": {"desc": "Partita vinta: attacco DDoS gestito con successo, sistema di difesa potenziato per il futuro.", "next": {}}
            },
            "step7_share": {
                "desc": "Il report è stato condiviso con il team di sicurezza e la direzione. Sono state pianificate azioni di miglioramento della sicurezza e formazione del personale.",
                "actions": [],
                "next": {"desc": "Partita vinta: attacco DDoS gestito con successo, organizzazione più resiliente.", "next": {}}
            },
            "step7_legal": {
                "desc": "L’attacco è stato denunciato alle autorità competenti. È stata avviata una collaborazione con un team di cybersecurity esterno per tracciare gli autori.",
                "actions": [],
                "next": {"desc": "Partita vinta: attacco DDoS gestito con successo, azioni legali avviate.", "next": {}}
            },
            "end_success": {"desc": "Attacco DDoS gestito con successo. Minaccia neutralizzata.", "actions": [], "next": {}},
            "end_partial": {"desc": "Risposta parziale. Attacco mitigato ma rischio residuo.", "actions": [], "next": {}},
            "end_fail": {"desc": "Risposta inadeguata. Attacco DDoS ha causato disservizio prolungato.", "actions": [], "next": {}}
        }
    },


  "lockbit3": {
    "name": "Attacco Ransomware LockBit 3.0",
    "optimal_steps": 7,
    "description": "Obiettivo: Identificare il vettore di infezione, contenere la diffusione del ransomware LockBit 3.0, recuperare i dati crittografati e garantire la sicurezza futura.",
    "states": {
      "step0": {
        "desc": "Il sistema di monitoraggio segnala attività sospette su un server di file sharing interno. Più file con estensione '.lockbit' sono stati rilevati. Il traffico di rete verso un IP esterno (185.196.245.12) è aumentato nelle ultime 2 ore.",
        "actions": [
          {
            "action": "Isola immediatamente il server di file sharing dalla rete.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "impact": "Contenimento urgente della diffusione."}
          },
          {
            "action": "Attiva il piano di Incident Response e notifica Management e Legal.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", "impact": "Allineamento organizzativo necessario."}
          },
          {
            "action": "Analizza i file '.lockbit' per identificare il ceppo di ransomware.",
            "cvss": {"score": 6.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Identificazione del malware."}
          },
          {
            "action": "Verifica connessioni RDP aperte o vulnerabili su altri server.",
            "cvss": {"score": 5.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Possibile identificazione del vettore."}
          }
        ],
        "next": {
          0: "step1_containment",
          1: "step1_notify",
          2: "step1_identify",
          3: "step1_check_rdp"
        }
      },
      "step1_notify": {
        "desc": "Il piano di Incident Response è stato attivato. Management e Legal sono stati informati. Canale di comunicazione sicuro stabilito.",
        "actions": [
          {
            "action": "Conferma catena di comando e ruoli nel team di risposta.",
            "cvss": {"score": 4.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", "impact": "Organizzazione del team."}
          },
          {
            "action": "Valuta obblighi di notifica normativa (GDPR) entro 72 ore.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", "impact": "Conformità legale."}
          },
          {
            "action": "Procedi con il contenimento tecnico.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "impact": "Ritorno al flusso tecnico."}
          }
        ],
        "next": {
          0: "step1_containment",
          1: "step1_containment",
          2: "step1_containment"
        }
      },
      "step1_identify": {
        "desc": "Analisi conferma LockBit 3.0. Ransomware usa RSA-2048 per crittografia. Nota di riscatto presente con ID univoco.",
        "actions": [
          {
            "action": "Documenta tutti gli IOC (Indicator of Compromise) trovati.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Documentazione per analisi futura."}
          },
          {
            "action": "Cerca backup recenti dei file crittografati.",
            "cvss": {"score": 7.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Possibile recupero dati."}
          },
          {
            "action": "Procedi con il contenimento tecnico.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "impact": "Priorità al contenimento."}
          }
        ],
        "next": {
          0: "step1_containment",
          1: "step1_containment",
          2: "step1_containment"
        }
      },
      "step1_check_rdp": {
        "desc": "Trovate sessioni RDP aperte non protette su server critici. Sessione compromessa da IP interno 192.168.1.105 identificata.",
        "actions": [
          {
            "action": "Disabilita temporaneamente accesso RDP su tutti i server.",
            "cvss": {"score": 8.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Blocco vettore di infezione."}
          },
          {
            "action": "Isola host 192.168.1.105 per analisi forense.",
            "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "impact": "Identificazione fonte."}
          },
          {
            "action": "Procedi con il contenimento tecnico.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "impact": "Priorità al contenimento."}
          }
        ],
        "next": {
          0: "step1_containment",
          1: "step1_containment",
          2: "step1_containment"
        }
      },
      "step1_containment": {
        "desc": "Server isolato. Traffico verso C2 (185.196.245.12) ancora attivo da alcuni host interni. Diffusione parzialmente contenuta.",
        "actions": [
          {
            "action": "Blocca tutto il traffico verso IP 185.196.245.12 a livello firewall.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Blocco comunicazione C2."}
          },
          {
            "action": "Identifica e isola tutti gli host che hanno comunicato con IP sospetto.",
            "cvss": {"score": 8.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Contenimento diffusione."}
          },
          {
            "action": "Preserva immagini di memoria e disco per forensics prima di pulizia.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", "impact": "Essenziale per analisi legale."}
          }
        ],
        "next": {
          0: "step2_eradication",
          1: "step2_eradication",
          2: "step2_eradication"
        }
      },
      "step2_eradication": {
        "desc": "Comunicazione con C2 bloccata. Host infetti isolati. Necessario rimuovere persistenza e preparare recovery.",
        "actions": [
          {
            "action": "Termina processi sospetti e rimuovi servizi di persistenza su tutti gli host.",
            "cvss": {"score": 8.5, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", "impact": "Rimozione completa minaccia."}
          },
          {
            "action": "Resetta tutte le credenziali amministrative e abilita MFA.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", "impact": "Previene reinfezione."}
          },
          {
            "action": "Applica patch di sicurezza critiche prima del recovery.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", "impact": "Chiude vulnerabilità sfruttate."}
          }
        ],
        "next": {
          0: "step3_recovery",
          1: "step3_recovery",
          2: "step3_recovery"
        }
      },
      "step3_recovery": {
        "desc": "Ambiente pulito e sicuro. Backup verificati integri (24 ore fa). Perdita stimata: 5GB dati modificati dopo ultimo backup.",
        "actions": [
          {
            "action": "Esegui recovery dei file dai backup verificati.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Recupero completo dati."}
          },
          {
            "action": "Verifica se recuperare dati persi da snapshot o shadow copies.",
            "cvss": {"score": 6.5, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Possibile recupero parziale."}
          },
          {
            "action": "Documenta perdita dati e informa utenti interessati.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Trasparenza verso stakeholder."}
          }
        ],
        "next": {
          0: "step4_validation",
          1: "step4_validation",
          2: "step4_validation"
        }
      },
      "step4_validation": {
        "desc": "Recovery completato. File ripristinati tranne 5GB dati recenti. Necessario validare pulizia completa ambiente.",
        "actions": [
          {
            "action": "Esegui scansione completa antivirus/EDR su tutti gli host.",
            "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Verifica pulizia ambiente."}
          },
          {
            "action": "Monitora traffico di rete per 48 ore per attività sospette residue.",
            "cvss": {"score": 7.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Rilevamento precoce reinfezione."}
          },
          {
            "action": "Verifica integrità sistemi critici prima di tornare in produzione.",
            "cvss": {"score": 8.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", "impact": "Garantisce sicurezza produzione."}
          }
        ],
        "next": {
          0: "step5_hardening",
          1: "step5_hardening",
          2: "step5_hardening"
        }
      },
      "step5_hardening": {
        "desc": "Ambiente validato pulito. Necessario implementare misure preventive per evitare futuri attacchi.",
        "actions": [
          {
            "action": "Implementa MFA obbligatorio per tutti gli accessi remoti (RDP, VPN).",
            "cvss": {"score": 8.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Riduce rischio accesso non autorizzato."}
          },
          {
            "action": "Segmenta rete per isolare server critici da workstation utente.",
            "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Contiene diffusione futura."}
          },
          {
            "action": "Implementa backup immutabili e test di recovery mensili.",
            "cvss": {"score": 8.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Garantisce recovery futuro."}
          }
        ],
        "next": {
          0: "step6_lessons",
          1: "step6_lessons",
          2: "step6_lessons"
        }
      },
      "step6_lessons": {
        "desc": "Misure preventive implementate. Necessario documentare incidente e condividere lessons learned.",
        "actions": [
          {
            "action": "Prepara report dettagliato per management con timeline e impatto.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Documentazione ufficiale."}
          },
          {
            "action": "Conduci sessione lessons learned con tutto il team IR.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Miglioramento processi futuri."}
          },
          {
            "action": "Aggiorna playbook di Incident Response basato su esperienza.",
            "cvss": {"score": 6.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Preparazione per futuri incidenti."}
          }
        ],
        "next": {
          0: "end_success",
          1: "end_success",
          2: "end_success"
        }
      },
      "end_success": {
        "desc": "SUCCESSO: Attacco ransomware LockBit 3.0 completamente gestito. Minaccia neutralizzata, dati recuperati, ambiente rafforzato. Incident closed.",
        "actions": [],
        "next": {}
      },
      "end_partial": {
        "desc": "PARZIALE: Attacco mitigato ma con perdita significativa di dati (>20%) o rischio residuo elevato. Monitoraggio continuo richiesto.",
        "actions": [],
        "next": {}
      },
      "end_fail": {
        "desc": "FALLIMENTO: Risposta inadeguata. Perdita massiva di dati, disservizio prolungato, o reinfezione confermata.",
        "actions": [],
        "next": {}
      }
    }
  },
  "ransomware_hospital": {
    "name": "Simulazione Attacco Ransomware Ospedaliero",
    "optimal_steps": 6,
    "description": "Obiettivo: Identificare il ransomware (LockBit 3.0), il vettore (phishing) e contenere l'attacco minimizzando l'impatto sui pazienti.",
    "states": {
      "step0": {
        "desc": "Segnalazione di blocco totale dei sistemi ospedalieri. Sui monitor appare un messaggio di riscatto: 'I tuoi dati sono cifrati. Paga 50 BTC per riottenere l'accesso.' Nessun allarme preventivo dai sistemi EDR. Il traffico di rete è anomalo: picco di connessioni SMB verso un server interno.",
        "actions": [
          {
            "action": "Isola immediatamente tutti i server dalla rete per fermare la diffusione.",
            "cvss": {"score": 9.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Contenimento aggressivo ma blocca sistemi critici per pazienti in cura."}
          },
          {
            "action": "Analizza il traffico di rete per identificare la fonte dell'infezione.",
            "cvss": {"score": 4.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Investigazione sicura, permette di capire prima di agire."}
          },
          {
            "action": "Verifica lo stato dei backup prima di qualsiasi azione.",
            "cvss": {"score": 3.5, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", "impact": "Valutazione cruciale per opzioni di recovery."}
          }
        ],
        "next": {
          0: "end_fail",
          1: "step1_investigate",
          2: "step1_backup_check"
        }
      },
      "step1_investigate": {
        "desc": "Analisi del traffico rivela connessioni anomale da un host interno (192.168.1.100) verso altri server. L'host è un PC del reparto amministrativo, usato da un dipendente che ha aperto un allegato email sospetto.",
        "actions": [
          {
            "action": "Elimina immediatamente tutti i file sospetti dalla rete senza analisi.",
            "cvss": {"score": 9.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", "impact": "Azione distruttiva, può eliminare prove forensi cruciali."}
          },
          {
            "action": "Isola l'host 192.168.1.100 e preserva evidenze forensi.",
            "cvss": {"score": 6.5, "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "impact": "Contenimento mirato con preservazione prove."}
          },
          {
            "action": "Cerca altri host con connessioni SMB anomale prima di isolare.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Mappatura completa dell'infezione prima di agire."}
          }
        ],
        "next": {
          0: "end_fail",
          1: "step2_containment",
          2: "step2_mapping"
        }
      },
      "step1_backup_check": {
        "desc": "I backup automatici sono cifrati e inutilizzabili. L'ultimo backup pulito risale a 7 giorni fa. Il sistema di backup era connesso alla rete principale.",
        "actions": [
          {
            "action": "Tenta di decifrare i backup con tool online (rischio di leak dati).",
            "cvss": {"score": 9.2, "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "impact": "Altissimo rischio di esporre dati sensibili a terzi."}
          },
          {
            "action": "Cerca backup offline o su nastro non connessi alla rete.",
            "cvss": {"score": 4.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Ricerca sicura di backup non compromessi."}
          },
          {
            "action": "Analizza come il ransomware ha raggiunto il server di backup.",
            "cvss": {"score": 5.5, "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "impact": "Comprensione vulnerabilità per prevenire reinfezioni."}
          }
        ],
        "next": {
          0: "end_fail",
          1: "step2_offline_backup",
          2: "step2_backup_analysis"
        }
      },
      "step2_mapping": {
        "desc": "Trovati altri 5 host con connessioni SMB anomale. Tutti appartengono al dominio ospedaliero e mostrano segni di cifratura. Il ransomware si sta diffondendo rapidamente.",
        "actions": [
          {
            "action": "Scollega fisicamente tutti i server ospedalieri dalla rete.",
            "cvss": {"score": 9.8, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Blocco totale servizi critici, rischio per pazienti in terapia intensiva."}
          },
          {
            "action": "Isola solo gli host infetti identificati, mantieni servizi critici attivi.",
            "cvss": {"score": 7.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Contenimento selettivo, minimizza impatto su pazienti."}
          },
          {
            "action": "Documenta tutti gli host infetti per analisi post-incidente.",
            "cvss": {"score": 3.5, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Documentazione importante ma non ferma la diffusione."}
          }
        ],
        "next": {
          0: "end_fail",
          1: "step2_containment",
          2: "step2_containment"
        }
      },
      "step2_containment": {
        "desc": "Host infetti isolati. Il ransomware non si diffonde più, ma i dati sono cifrati. Servizi critici (pronto soccorso, terapia intensiva) ancora operativi su sistemi manuali.",
        "actions": [
          {
            "action": "Contatta immediatamente gli attaccanti per negoziare il riscatto.",
            "cvss": {"score": 8.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Rischio legale, finanziario e di incentivare futuri attacchi."}
          },
          {
            "action": "Verifica integrità backup offline trovato (3 giorni fa).",
            "cvss": {"score": 5.0, "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Valutazione sicura opzione di recovery."}
          },
          {
            "action": "Analizza il malware per trovare eventuali decryptor pubblici.",
            "cvss": {"score": 6.0, "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Ricerca soluzione tecnica senza pagare riscatto."}
          }
        ],
        "next": {
          0: "end_partial",
          1: "step3_recovery_prep",
          2: "step3_decryptor_search"
        }
      },
      "step2_offline_backup": {
        "desc": "Trovato backup offline su nastro risalente a 3 giorni fa. Non compromesso, può essere usato per recovery. Perdita stimata: 3 giorni di dati non critici.",
        "actions": [
          {
            "action": "Ripristina immediatamente tutti i dati senza verificare integrità.",
            "cvss": {"score": 8.8, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "impact": "Rischio di ripristinare malware o dati corrotti."}
          },
          {
            "action": "Verifica integrità backup in ambiente isolato prima del restore.",
            "cvss": {"score": 5.5, "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Verifica sicura previene reinfezione."}
          },
          {
            "action": "Documenta stato backup per report management.",
            "cvss": {"score": 3.0, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Documentazione utile ma non azione operativa."}
          }
        ],
        "next": {
          0: "end_fail",
          1: "step3_recovery_prep",
          2: "step3_recovery_prep"
        }
      },
      "step2_backup_analysis": {
        "desc": "Il ransomware ha raggiunto il server di backup tramite RDP aperto con password debole. Account amministratore compromesso.",
        "actions": [
          {
            "action": "Resetta tutte le password di dominio immediatamente (blocca accessi legittimi).",
            "cvss": {"score": 9.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", "impact": "Blocco totale accessi, impatto su personale medico."}
          },
          {
            "action": "Resetta password account amministrativi compromessi, mantieni altri attivi.",
            "cvss": {"score": 6.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", "impact": "Contenimento mirato, minimizza impatto operativo."}
          },
          {
            "action": "Analizza log RDP per identificare estensione compromissione.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Comprensione completa prima di agire."}
          }
        ],
        "next": {
          0: "end_partial",
          1: "step3_cred_reset",
          2: "step3_cred_reset"
        }
      },
      "step3_recovery_prep": {
        "desc": "Backup verificato integro. Piano di recovery pronto: ripristino graduale servizi critici primi, poi amministrativi. Tempo stimato: 12 ore.",
        "actions": [
          {
            "action": "Ripristina tutti i sistemi contemporaneamente per velocizzare.",
            "cvss": {"score": 8.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "impact": "Rischio di sovraccarico e errori, difficile rollback se problemi."}
          },
          {
            "action": "Ripristina prima servizi critici (pronto soccorso, farmacia), poi altri.",
            "cvss": {"score": 6.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "impact": "Priorità corretta, minimizza rischio per pazienti."}
          },
          {
            "action": "Documenta piano di recovery per audit e compliance.",
            "cvss": {"score": 3.5, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Documentazione necessaria ma non azione operativa."}
          }
        ],
        "next": {
          0: "end_partial",
          1: "step4_recovery",
          2: "step4_recovery"
        }
      },
      "step3_decryptor_search": {
        "desc": "Ricerca decryptor pubblici non ha trovato soluzioni per LockBit 3.0. Il gruppo usa crittografia RSA-2048 senza vulnerabilità note. Recovery da backup è l'unica opzione.",
        "actions": [
          {
            "action": "Prova tool di decryptor non verificati da fonti dubbie.",
            "cvss": {"score": 9.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "impact": "Altissimo rischio di malware aggiuntivo o damage ai file."}
          },
          {
            "action": "Procedi con recovery da backup offline verificato.",
            "cvss": {"score": 6.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "impact": "Soluzione sicura e verificata."}
          },
          {
            "action": "Documenta ricerca decryptor per report finale.",
            "cvss": {"score": 3.0, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Documentazione utile per knowledge base."}
          }
        ],
        "next": {
          0: "end_fail",
          1: "step4_recovery",
          2: "step4_recovery"
        }
      },
      "step3_cred_reset": {
        "desc": "Password amministrative resetate. MFA implementato per tutti gli accessi remoti. RDP disabilitato per account non essenziali.",
        "actions": [
          {
            "action": "Riapri immediatamente tutti gli accessi RDP per operatività.",
            "cvss": {"score": 8.8, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", "impact": "Riapre vulnerabilità sfruttata, rischio reinfezione."}
          },
          {
            "action": "Mantieni RDP disabilitato, usa VPN con MFA per accessi remoti.",
            "cvss": {"score": 5.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Soluzione sicura con accesso controllato."}
          },
          {
            "action": "Documenta nuove policy di accesso per compliance.",
            "cvss": {"score": 3.5, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Documentazione necessaria per audit."}
          }
        ],
        "next": {
          0: "end_partial",
          1: "step4_recovery",
          2: "step4_recovery"
        }
      },
      "step4_recovery": {
        "desc": "Recovery in corso. Servizi critici ripristinati. Dati non critici (3 giorni) persi. Nessun impatto su pazienti in cura.",
        "actions": [
          {
            "action": "Riconnetti immediatamente tutti i sistemi alla rete principale.",
            "cvss": {"score": 8.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Rischio di reinfezione se residui malware presenti."}
          },
          {
            "action": "Verifica pulizia completa con scansione EDR prima di riconnettere.",
            "cvss": {"score": 6.0, "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Verifica sicura previene reinfezione."}
          },
          {
            "action": "Documenta stato recovery per comunicazione stakeholders.",
            "cvss": {"score": 4.0, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Comunicazione importante per trasparenza."}
          }
        ],
        "next": {
          0: "end_partial",
          1: "step5_validation",
          2: "step5_validation"
        }
      },
      "step5_validation": {
        "desc": "Scansione EDR completa: nessun residuo malware trovato. Sistemi puliti e operativi. Necessario implementare misure preventive.",
        "actions": [
          {
            "action": "Implementa tutte le misure di sicurezza contemporaneamente (downtime esteso).",
            "cvss": {"score": 8.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "impact": "Impatto operativo significativo su servizi ospedalieri."}
          },
          {
            "action": "Implementa misure critiche prime (MFA, segmentazione), poi altre gradualmente.",
            "cvss": {"score": 6.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Bilanciamento sicurezza e operatività."}
          },
          {
            "action": "Documenta misure implementate per audit e compliance.",
            "cvss": {"score": 4.0, "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "impact": "Documentazione necessaria per certificazioni."}
          }
        ],
        "next": {
          0: "end_partial",
          1: "step6_lessons",
          2: "step6_lessons"
        }
      },
      "step6_lessons": {
        "desc": "Misure preventive implementate: MFA obbligatorio, segmentazione rete, backup immutabili, training phishing per staff. Incidente chiuso.",
        "actions": [
          {
            "action": "Prepara report dettagliato per management e autorità GDPR.",
            "cvss": {"score": 4.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "impact": "Compliance normativa e trasparenza."}
          },
          {
            "action": "Conduci sessione lessons learned con tutto il team IT e medico.",
            "cvss": {"score": 5.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Miglioramento processi futuri."}
          },
          {
            "action": "Aggiorna playbook Incident Response basato su esperienza.",
            "cvss": {"score": 5.5, "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", "impact": "Preparazione per futuri incidenti."}
          }
        ],
        "next": {
          0: "end_success",
          1: "end_success",
          2: "end_success"
        }
      },
      "end_success": {
        "desc": "SUCCESSO: Incidente gestito correttamente. Minaccia contenuta, dati recuperati da backup, nessun impatto su pazienti. Misure preventive implementate.",
        "actions": [],
        "next": {}
      },
      "end_partial": {
        "desc": "PARZIALE: Incidente mitigato ma con conseguenze. Perdita dati significativa, downtime esteso, o rischio residuo elevato. Monitoraggio continuo richiesto.",
        "actions": [],
        "next": {}
      },
      "end_fail": {
        "desc": "FALLIMENTO: Risposta inadeguata. Azioni troppo aggressive hanno causato danni maggiori dell'attacco stesso. Pazienti interessati, dati persi permanentemente, o reinfezione confermata.",
        "actions": [],
        "next": {}
      }
    }
  }
}





# 4) Caricamento dei modelli

# --- CARICAMENTO DEL MODELLO LLaMA-3.2-3B-Instruct-bnb-4bit ---
def load_llama3_model():
    if not UNSLOTH_AVAILABLE:
        return None, None
    try:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name="unsloth/Llama-3.2-3B-Instruct-bnb-4bit",
            max_seq_length=2048,
            dtype=torch.float16,
            load_in_4bit=True,
            trust_remote_code=True,
        )
        print("✅ Modello Llama-3.2-3B-Instruct-bnb-4bit caricato con successo!")
        return model, tokenizer
    except Exception as e:
        print(f"❌ Errore nel caricamento del modello Llama-3.2: {e}")
        return None, None

# --- CARICAMENTO DEL MODELLO Qwen2.5-3B-Instruct-bnb-4bit ---
def load_qwen_model():
    if not UNSLOTH_AVAILABLE:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            model_name = "Qwen/Qwen2.5-3B-Instruct"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
                load_in_4bit=True if torch.cuda.is_available() else False,
            )
            print("✅ Modello Qwen2.5-3B-Instruct caricato con transformers!")
            return model, tokenizer
        except Exception as e:
            print(f"❌ Errore nel caricamento del modello Qwen: {e}")
            return None, None

    try:
        from unsloth import FastLanguageModel
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name="unsloth/Qwen2.5-3B-Instruct-bnb-4bit",
            max_seq_length=2048,
            dtype=torch.float16,
            load_in_4bit=True,
        )
        print("✅ Modello Qwen2.5-3B-Instruct-bnb-4bit caricato con successo!")
        return model, tokenizer
    except Exception as e:
        print(f"❌ Errore nel caricamento del modello Qwen con Unsloth: {e}")
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            model_name = "Qwen/Qwen2.5-3B-Instruct"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
            )
            print("✅ Fallback: Modello Qwen caricato con transformers standard.")
            return model, tokenizer
        except:
            return None, None

# --- CARICAMENTO DEL MODELLO Mistral-7B ---
def load_mistral_model():
    if not UNSLOTH_AVAILABLE:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            model_name = "mistralai/Mistral-7B-Instruct-v0.2"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
                load_in_4bit=True if torch.cuda.is_available() else False,
            )
            print("✅ Modello Mistral-7B-Instruct-v0.2 caricato con transformers!")
            return model, tokenizer
        except Exception as e:
            print(f"❌ Errore nel caricamento del modello Mistral: {e}")
            return None, None

    try:
        from unsloth import FastLanguageModel
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name="unsloth/mistral-7b-instruct-v0.2-bnb-4bit",
            max_seq_length=2048,
            dtype=torch.float16,
            load_in_4bit=True,
        )
        print("✅ Modello Mistral-7B-Instruct-v0.2-bnb-4bit caricato con successo!")
        return model, tokenizer
    except Exception as e:
        print(f"❌ Errore nel caricamento del modello Mistral con Unsloth: {e}")
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            model_name = "mistralai/Mistral-7B-Instruct-v0.2"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
            )
            print("✅ Fallback: Modello Mistral caricato con transformers standard.")
            return model, tokenizer
        except:
            return None, None

# --- CARICAMENTO DEL MODELLO Gemma-2B-IT ---
def load_gemma_model():
    if not UNSLOTH_AVAILABLE:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            model_name = "google/gemma-2b-it"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
                load_in_4bit=True if torch.cuda.is_available() else False,
            )
            print("✅ Modello Gemma-2B-IT caricato con transformers!")
            return model, tokenizer
        except Exception as e:
            print(f"❌ Errore nel caricamento del modello Gemma: {e}")
            return None, None

    try:
        from unsloth import FastLanguageModel
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name="unsloth/gemma-2b-it-bnb-4bit",
            max_seq_length=2048,
            dtype=torch.float16,
            load_in_4bit=True,
        )
        print("✅ Modello Gemma-2B-IT-bnb-4bit caricato con successo!")
        return model, tokenizer
    except Exception as e:
        print(f"❌ Errore nel caricamento del modello Gemma con Unsloth: {e}")
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            model_name = "google/gemma-2b-it"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
            )
            print("✅ Fallback: Modello Gemma caricato con transformers standard.")
            return model, tokenizer
        except:
            return None, None






# 5) Definizione degli agenti
# --- AGENTI DISPONIBILI ---
def cvss_agent(state_desc: str, actions: List[Dict], state: Dict, scenario: str, current_step: str) -> Tuple[int, str]:
    """Agente che sceglie l'azione con il CVSS più alto."""
    best_action_idx = max(range(len(actions)), key=lambda i: actions[i]["cvss"]["score"])
    reasoning = f"""
    L'agente 'CVSS Agent' ha scelto l'azione con il CVSS più alto:
    - Azione: "{actions[best_action_idx]['action']}"
    - CVSS: {actions[best_action_idx]['cvss']['score']}
    - Motivo: Massimizzazione del punteggio di rischio/impatto.
    """
    return best_action_idx, reasoning

def random_agent(state_desc: str, actions: List[Dict], state: Dict, scenario: str, current_step: str) -> Tuple[int, str]:
    """Agente che sceglie un'azione casuale."""
    import random
    best_action_idx = random.randint(0, len(actions)-1)
    reasoning = f"""
    L'agente 'Random Agent' ha scelto un'azione casuale:
    - Azione: "{actions[best_action_idx]['action']}"
    - CVSS: {actions[best_action_idx]['cvss']['score']}
    - Motivo: Scelta casuale (per testare la robustezza del benchmark).
    """
    return best_action_idx, reasoning

def llama3_agent(model, tokenizer, state_desc: str, actions: List[Dict], state: Dict, scenario: str, current_step: str) -> Tuple[int, str]:
    prompt = f"""
    Sei un esperto di cybersecurity. Analizza questo scenario e scegli l'azione più appropriata per gestire al meglio un attacco.

    --- SCENARIO ---
    {state_desc}

    --- AZIONI POSSIBILI ---
    {chr(10).join([f"{i+1}. {act['action']}" for i, act in enumerate(actions)])}

    --- ISTRUZIONI ---
    Rispondi SOLO con il numero dell'azione scelta (es. "1"), senza altre parole.
    NON focalizzarti sui CVSS. Da priorità alla riuscita della gestione dell'attacco, evitando soprattutti vicoli ciechi.
    """

    try:
        inputs = tokenizer(
            [prompt],
            return_tensors="pt",
            padding=False,
            truncation=True,
            max_length=1024,
        ).to("cuda" if torch.cuda.is_available() else "cpu")

        # --- SOLUZIONE: Forza la rimozione di max_length ---
        generation_config = model.generation_config
        if hasattr(generation_config, "max_length"):
            generation_config.max_length = None  # Disabilita max_length

        outputs = model.generate(
            input_ids=inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_new_tokens=1,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            do_sample=True,
            temperature=0.4,
        )

        response = tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:],
            skip_special_tokens=True
        ).strip()

        chosen_idx = 0
        if response and response[0].isdigit():
            chosen_idx = int(response[0]) - 1
            chosen_idx = max(0, min(chosen_idx, len(actions)-1))

        reasoning = f"L'agente Llama-3.2 ha scelto l'azione {chosen_idx+1}: {actions[chosen_idx]['action']}"
        return chosen_idx, reasoning

    except Exception as e:
        print(f"❌ Errore in Llama-3.2: {e}")
        return 0, f"Errore nel modello: {e}. Scelta default: {actions[0]['action']}"

def qwen_agent(model, tokenizer, state_desc: str, actions: List[Dict], state: Dict, scenario: str, current_step: str) -> Tuple[int, str]:
    """Agente basato su Qwen2.5-3B-Instruct, con prompt ottimizzato per cybersecurity."""
    messages = [
        {"role": "system", "content": "Sei un esperto di cybersecurity incaricato di analizzare scenari di attacco e scegliere le azioni di risposta più appropriate. Rispondi SOLO con il numero dell'azione (es. '1')."},
        {"role": "user", "content": f"""
### Scenario:
{state_desc}

### Azioni disponibili:
{chr(10).join([f"{i+1}. {act['action']}" for i, act in enumerate(actions)])}

### Istruzioni:
Scegli l'azione più appropriata e rispondi SOLO con il numero (es. '2')."""}
    ]

    try:
        # Applica chat template se disponibile
        if hasattr(tokenizer, 'apply_chat_template'):
            prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            prompt = messages[0]["content"] + "\n\n" + messages[1]["content"]

        # Tokenizza con truncation a 1024 token per evitare conflitti di shape
        inputs = tokenizer(
            [prompt],
            return_tensors="pt",
            padding=False,
            truncation=True,
            max_length=1024,  # Limita la lunghezza del prompt
        ).to("cuda" if torch.cuda.is_available() else "cpu")

        # Disabilita max_length per evitare il warning
        generation_config = model.generation_config
        if hasattr(generation_config, "max_length"):
            generation_config.max_length = None

        # Genera con max_new_tokens=16 (sufficiente per una risposta completa)
        outputs = model.generate(
            input_ids=inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_new_tokens=16,  # Permette una risposta completa
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            do_sample=False,
            temperature=0.1,
        )

        # Decodifica l'intera risposta
        response = tokenizer.batch_decode(outputs, skip_special_tokens=True)[0].strip()

        # Estrai il primo numero valido (1-9) dalla risposta
        chosen_idx = 0
        import re
        numbers = re.findall(r'\b[1-9]\b', response)
        if numbers:
            chosen_idx = int(numbers[0]) - 1
            chosen_idx = max(0, min(chosen_idx, len(actions)-1))  # Clamp nell'intervallo valido

        reasoning = f"L'agente Qwen2.5 ha scelto l'azione {chosen_idx+1}: '{actions[chosen_idx]['action']}' (CVSS: {actions[chosen_idx]['cvss']['score']})"
        return chosen_idx, reasoning

    except Exception as e:
        print(f"❌ Errore in Qwen agent: {e}")
        return 0, f"Errore nel modello Qwen: {e}. Scelta fallback: azione 1."

def mistral_agent(model, tokenizer, state_desc: str, actions: List[Dict], state: Dict, scenario: str, current_step: str) -> Tuple[int, str]:
    messages = [
        {"role": "system", "content": "Sei un esperto di cybersecurity. Analizza lo scenario e scegli l'azione più appropriata. Rispondi SOLO con il numero dell'azione (es. '1'), senza spiegazioni."},
        {"role": "user", "content": f"""
        ### Scenario:
        {state_desc}

        ### Azioni disponibili:
        {chr(10).join([f"{i+1}. {act['action']}" for i, act in enumerate(actions)])}

        ### Istruzioni:
        Scegli l'azione più logica e sicura per la situazione attuale. Rispondi SOLO con il numero dell'azione (es. '1')."""}
    ]

    try:
        if hasattr(tokenizer, 'apply_chat_template'):
            prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            prompt = messages[0]["content"] + "\n\n" + messages[1]["content"]

        inputs = tokenizer(
            [prompt],
            return_tensors="pt",
            padding=False,
            truncation=True,
            max_length=1024,
        ).to("cuda" if torch.cuda.is_available() else "cpu")

        # --- SOLUZIONE: Disabilita max_length per evitare il warning ---
        generation_config = model.generation_config
        if hasattr(generation_config, "max_length"):
            generation_config.max_length = None

        outputs = model.generate(
            **inputs,
            max_new_tokens=1,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            do_sample=False,
            temperature=0.1,
        )

        response = tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:],
            skip_special_tokens=True
        ).strip()

        chosen_idx = 0
        if response and response[0].isdigit():
            chosen_idx = int(response[0]) - 1
            chosen_idx = max(0, min(chosen_idx, len(actions)-1))

        reasoning = f"L'agente Mistral-7B ha scelto l'azione {chosen_idx+1}: '{actions[chosen_idx]['action']}' (CVSS: {actions[chosen_idx]['cvss']['score']})"
        return chosen_idx, reasoning

    except Exception as e:
        print(f"❌ Errore in Mistral agent: {e}")
        return 0, f"Errore nel modello Mistral: {e}. Scelta fallback: azione 1."

def gemma_agent(model, tokenizer, state_desc: str, actions: List[Dict], state: Dict, scenario: str, current_step: str) -> Tuple[int, str]:
    prompt = f"""
    Sei un esperto di cybersecurity. Analizza questo scenario e scegli l'azione più appropriata.

    --- SCENARIO ---
    {state_desc}

    --- AZIONI POSSIBILI ---
    {chr(10).join([f"{i+1}. {act['action']}" for i, act in enumerate(actions)])}

    --- ISTRUZIONI ---
    Rispondi SOLO con il numero dell'azione scelta (es. "1"), senza altre parole.
    """

    try:
        inputs = tokenizer(
            [prompt],
            return_tensors="pt",
            padding=False,
            truncation=True,
            max_length=1024,
        ).to("cuda" if torch.cuda.is_available() else "cpu")

        # --- SOLUZIONE: Disabilita max_length per evitare il warning ---
        generation_config = model.generation_config
        if hasattr(generation_config, "max_length"):
            generation_config.max_length = None

        outputs = model.generate(
            **inputs,
            max_new_tokens=1,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            do_sample=False,
            temperature=0.1,
        )

        response = tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:],
            skip_special_tokens=True
        ).strip()

        chosen_idx = 0
        if response and response[0].isdigit():
            chosen_idx = int(response[0]) - 1
            chosen_idx = max(0, min(chosen_idx, len(actions)-1))

        reasoning = f"L'agente Gemma-2B ha scelto l'azione {chosen_idx+1}: '{actions[chosen_idx]['action']}' (CVSS: {actions[chosen_idx]['cvss']['score']})"
        return chosen_idx, reasoning

    except Exception as e:
        print(f"❌ Errore in Gemma agent: {e}")
        return 0, f"Errore nel modello Gemma: {e}. Scelta fallback: azione 1."






# 6) Menu di scelta dell'agente
# --- MENU DI SCELTA DELL'AI ---
def choose_agent():
    print("\n🤖 SCEGLI L'AI/AGENTE DA UTILIZZARE:")
    print("1. CVSS Agent (sceglie l'azione con il CVSS più alto)")
    print("2. Random Agent (sceglie un'azione casuale)")
    if UNSLOTH_AVAILABLE:
        print("3. Llama-3.2-3B-Instruct-bnb-4bit (AI avanzata)")
        print("4. Qwen2.5-3B-Instruct-bnb-4bit (AI avanzata - alternativa)")
        print("5. Mistral-7B-Instruct-v0.2 (AI avanzata, open-source)")
        print("6. Gemma-2B-IT (AI leggera e veloce, open-source)")
    else:
        print("3. Qwen2.5-3B-Instruct (AI avanzata - versione standard)")
        print("4. Mistral-7B-Instruct-v0.2 (AI avanzata, open-source)")
        print("5. Gemma-2B-IT (AI leggera e veloce, open-source)")

    choice = input("Inserisci il numero dell'agente: ").strip()

    if choice == "1":
        return cvss_agent, "CVSS Agent"
    elif choice == "2":
        return random_agent, "Random Agent"
    elif choice == "3" and UNSLOTH_AVAILABLE:
        model, tokenizer = load_llama3_model()
        if model is None:
            print("⚠️ Modello Llama-3.2 non disponibile. Usato CVSS Agent come fallback.")
            return cvss_agent, "CVSS Agent (fallback)"
        return lambda *args: llama3_agent(model, tokenizer, *args), "Llama-3.2-3B-Instruct-bnb-4bit"
    elif choice == "4" and UNSLOTH_AVAILABLE:
        model, tokenizer = load_qwen_model()
        if model is None:
            print("⚠️ Modello Qwen non disponibile. Usato CVSS Agent come fallback.")
            return cvss_agent, "CVSS Agent (fallback)"
        return lambda *args: qwen_agent(model, tokenizer, *args), "Qwen2.5-3B-Instruct-bnb-4bit"
    elif choice == "3" and not UNSLOTH_AVAILABLE:
        model, tokenizer = load_qwen_model()
        if model is None:
            print("⚠️ Modello Qwen non disponibile. Usato CVSS Agent come fallback.")
            return cvss_agent, "CVSS Agent (fallback)"
        return lambda *args: qwen_agent(model, tokenizer, *args), "Qwen2.5-3B-Instruct"
    elif choice == "4" and not UNSLOTH_AVAILABLE:
        model, tokenizer = load_mistral_model()
        if model is None:
            print("⚠️ Modello Mistral non disponibile. Usato CVSS Agent come fallback.")
            return cvss_agent, "CVSS Agent (fallback)"
        return lambda *args: mistral_agent(model, tokenizer, *args), "Mistral-7B-Instruct-v0.2"
    elif choice == "5" and not UNSLOTH_AVAILABLE:
        model, tokenizer = load_gemma_model()
        if model is None:
            print("⚠️ Modello Gemma non disponibile. Usato CVSS Agent come fallback.")
            return cvss_agent, "CVSS Agent (fallback)"
        return lambda *args: gemma_agent(model, tokenizer, *args), "Gemma-2B-IT"
    elif choice == "5" and UNSLOTH_AVAILABLE:
        model, tokenizer = load_mistral_model()
        if model is None:
            print("⚠️ Modello Mistral non disponibile. Usato CVSS Agent come fallback.")
            return cvss_agent, "CVSS Agent (fallback)"
        return lambda *args: mistral_agent(model, tokenizer, *args), "Mistral-7B-Instruct-v0.2"
    elif choice == "6" and UNSLOTH_AVAILABLE:
        model, tokenizer = load_gemma_model()
        if model is None:
            print("⚠️ Modello Gemma non disponibile. Usato CVSS Agent come fallback.")
            return cvss_agent, "CVSS Agent (fallback)"
        return lambda *args: gemma_agent(model, tokenizer, *args), "Gemma-2B-IT"
    else:
        return cvss_agent, "CVSS Agent (default)"






# 7) CybersecurityBenchmak
class CybersecurityBenchmark:
    def __init__(self, scenarios: Dict):
        self.scenarios = scenarios
        self.operational_metrics = {
            "downtime_minutes": 0,
            "cpu_usage_percent": 0,
            "memory_usage_mb": 0,
            "bandwidth_mb": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "action_costs": 0,
            "data_exfiltrated_mb": 0,
            "avg_cvss_score": 0,
            "max_cvss_score": 0,
            "premature_reports": 0,
            "critical_actions_taken": 0,
            "dead_end_actions": 0,
            "consecutive_logical_actions": 0,
            "investigation_depth": 0,
            "high_cvss_ratio": 0.0,
            "contextual_high_cvss": 0,
            "action_variety": 0,
            "health": 100,  # Gamification: "vita" dell'agente
            "partial_scores": [],  # Punteggi parziali ad ogni step
        }
        self.action_history = []
        self.cvss_history = []

    def reset_metrics(self):
        self.operational_metrics = {k: 0 for k in self.operational_metrics}
        self.operational_metrics["health"] = 100
        self.operational_metrics["partial_scores"] = []
        self.action_history = []
        self.cvss_history = []

    def calculate_efficiency_bonus(self, steps: int, optimal_steps: int, max_bonus: float = 40.0, decay_rate: float = 0.25) -> float:
        if steps == 0:
            return 0.0
        deviation = abs(steps - optimal_steps)
        bonus = max_bonus * ((1 - decay_rate) ** deviation)
        return max(0.0, min(max_bonus, bonus))

    def calculate_cvss_behavior_penalty(self, metrics: Dict) -> float:
        penalty = 0.0
        variety = metrics.get("action_variety", 1)
        if variety < 0.3:
            penalty += (0.3 - variety) * 30
        return penalty

    def calculate_coherence_bonus(self, metrics: Dict) -> float:
        consecutive = metrics.get("consecutive_logical_actions", 0)
        investigation_depth = metrics.get("investigation_depth", 0)
        contextual_high_cvss = metrics.get("contextual_high_cvss", 0)
        coherence_score = 0
        if consecutive >= 1: coherence_score += 2
        if consecutive >= 2: coherence_score += 3
        if consecutive >= 3: coherence_score += 4
        if consecutive >= 4: coherence_score += 6
        coherence_score = min(15.0, coherence_score)
        depth_bonus = min(10.0, investigation_depth * 2.5)
        cvss_context_bonus = min(5.0, contextual_high_cvss * 2.5)
        return coherence_score + depth_bonus + cvss_context_bonus

    def calculate_reasoning_score(self, metrics: Dict, result: Dict) -> float:
        score = 0.0
        if result.get("status") == "win":
            score += 15
            if result.get("vettore_identificato", False):
                score += 3
            if result.get("obiettivo_identificato", False):
                score += 3
            if result.get("contenimento_efficace", False):
                score += 4
        critical_actions = metrics.get("critical_actions_taken", 0)
        investigation_bonus = min(20.0, critical_actions * 5)
        score += investigation_bonus
        if metrics.get("data_exfiltrated_mb", 0) == 0 and metrics.get("downtime_minutes", 0) == 0:
            score += 10
        coherence_bonus = self.calculate_coherence_bonus(metrics)
        score += coherence_bonus
        penalties = 0.0
        premature = metrics.get("premature_reports", 0)
        penalties += premature * 15
        dead_ends = metrics.get("dead_end_actions", 0)
        penalties += dead_ends * 8
        fp_fn = metrics.get("false_positives", 0) + metrics.get("false_negatives", 0)
        penalties += fp_fn * 5
        cvss_behavior_penalty = self.calculate_cvss_behavior_penalty(metrics)
        penalties += cvss_behavior_penalty
        high_cvss_ratio = metrics.get("high_cvss_ratio", 0)
        contextual_high_cvss = metrics.get("contextual_high_cvss", 0)
        if high_cvss_ratio > 0.5 and contextual_high_cvss / max(1, metrics.get("critical_actions_taken", 1)) < 0.3:
            penalties += 30
        return max(0.0, score - penalties)

    def calculate_partial_score(self, steps: int, scenario: Dict, metrics: Dict, result: Dict) -> float:
        """Calcola il punteggio parziale ad ogni step."""
        optimal_steps = scenario.get("optimal_steps", 1)
        if steps == 0:
            return 0.0
        efficiency_score = self.calculate_efficiency_bonus(steps, optimal_steps, 20.0, 0.3)
        reasoning_score = self.calculate_reasoning_score(metrics, result)
        health_penalty = (100 - metrics.get("health", 100)) * 0.2
        partial_score = efficiency_score + reasoning_score - health_penalty
        return max(0.0, min(100.0, partial_score))

    def calculate_final_score(self, steps: int, scenario: Dict, metrics: Dict, result: Dict) -> float:
        optimal_steps = scenario.get("optimal_steps", 1)
        if steps == 0:
            return 0.0
        efficiency_score = self.calculate_efficiency_bonus(steps, optimal_steps, 40.0, 0.25)
        reasoning_score = self.calculate_reasoning_score(metrics, result)
        health_penalty = (100 - metrics.get("health", 100)) * 0.3
        final_score = efficiency_score + reasoning_score - health_penalty
        return max(0.0, min(100.0, final_score))

    def _is_logical_action_sequence(self, prev_action: str, curr_action: str) -> bool:
        if not prev_action:
            return True
        prev_lower = prev_action.lower()
        curr_lower = curr_action.lower()
        logical_sequences = [
            ("richiedi", "analizza"),
            ("analizza", "verifica"),
            ("analizza", "blocca"),
            ("verifica", "cerca"),
            ("cerca", "isola"),
            ("scansione", "analizza"),
            ("verifica", "analizza"),
            ("cerca", "analizza"),
        ]
        for prev_keyword, curr_keyword in logical_sequences:
            if prev_keyword in prev_lower and curr_keyword in curr_lower:
                return True
        investigation_keywords = ["analizza", "verifica", "cerca", "richiedi", "scansione"]
        report_keywords = ["rapporto", "report"]
        is_investigation = any(k in curr_lower for k in investigation_keywords)
        was_report = any(k in prev_lower for k in report_keywords)
        if is_investigation and not was_report:
            return True
        return False

    def run_benchmark(
        self,
        scenario_key: str,
        agent_function: Callable,
        agent_name: str,
        max_steps: int = 10,
        verbose: bool = True
    ) -> Dict:
        self.reset_metrics()
        scenario = self.scenarios.get(scenario_key)
        if scenario is None:
            print(f"❌ Scenario '{scenario_key}' non trovato.")
            return {"status": "error", "score": 0, "metrics": self.operational_metrics, "agent": agent_name}

        states = scenario["states"]
        current = "step0"
        steps = 0
        history = []
        prev_action = None
        prev_action_type = None
        consecutive_logical = 0
        high_cvss_count = 0
        contextual_high_cvss_count = 0
        action_types = set()

        if verbose:
            print("="*80)
            print(f"📊 BENCHMARK: {scenario['name']}")
            print(f"🎯 Obiettivo: {scenario['description']}")
            print(f"🤖 AI/AGENTE: {agent_name}")
            print("="*80)

        while steps < max_steps:
            state = states.get(current)
            if state is None:
                break
            history.append(state["desc"])

            if verbose:
                print(f"\n🔹 STEP {steps}")
                print(f"📌 CONTESTO:\n{state['desc']}\n")

            if "win" in current or current.startswith("end_success"):
                total_actions = max(1, steps)
                self.operational_metrics["high_cvss_ratio"] = high_cvss_count / total_actions
                self.operational_metrics["contextual_high_cvss"] = contextual_high_cvss_count
                self.operational_metrics["action_variety"] = len(action_types) / max(1, total_actions)
                result = {
                    "status": "win", "attacco_identificato": True, "vettore_identificato": True,
                    "obiettivo_identificato": True, "contenimento_efficace": True,
                    "steps": steps, "history": history, "terminal": current
                }
                score = self.calculate_final_score(steps, scenario, self.operational_metrics, result)
                if verbose:
                    print("\n📊 RISULTATO: Attacco gestito con successo.")
                    print(f"✅ Punteggio finale: {score:.1f}/100")
                return {**result, "score": score, "metrics": self.operational_metrics, "agent": agent_name}

            if not state["actions"]:
                total_actions = max(1, steps)
                self.operational_metrics["high_cvss_ratio"] = high_cvss_count / total_actions
                self.operational_metrics["contextual_high_cvss"] = contextual_high_cvss_count
                self.operational_metrics["action_variety"] = len(action_types) / max(1, total_actions)
                result = {
                    "status": "loss" if current == "end_fail" else "partial",
                    "steps": steps, "history": history, "terminal": current
                }
                score = self.calculate_final_score(steps, scenario, self.operational_metrics, result)
                if verbose:
                    print(f"\n📊 RISULTATO: {'Attacco parzialmente gestito' if result['status'] == 'partial' else 'Attacco non gestito'}")
                    print(f"❌ Punteggio finale: {score:.1f}/100")
                return {**result, "score": score, "metrics": self.operational_metrics, "agent": agent_name}

            if verbose:
                print("🔍 AZIONI POSSIBILI:")
                for i, act in enumerate(state["actions"], 1):
                    print(f" {i}. {act['action']} (CVSS: {act['cvss']['score']})")

            try:
                action_idx, reasoning = agent_function(state["desc"], state["actions"], state, scenario_key, current)
            except Exception as e:
                action_idx = -1

            if action_idx == -1:
                result = {"status": "loss", "steps": steps, "history": history, "terminal": "end_fail"}
                score = self.calculate_final_score(steps, scenario, self.operational_metrics, result)
                if verbose:
                    print(f"\n❌ Punteggio finale: {score:.1f}/100")
                return {**result, "score": score, "metrics": self.operational_metrics, "agent": agent_name}

            chosen_action = state["actions"][action_idx]["action"]
            chosen_cvss = state["actions"][action_idx]["cvss"]["score"]
            next_state = state["next"].get(action_idx, "end_fail")

            action_lower = chosen_action.lower()
            if "analizza" in action_lower or "scansione" in action_lower:
                current_action_type = "analysis"
                action_types.add("analysis")
            elif "verifica" in action_lower or "cerca" in action_lower:
                current_action_type = "verification"
                action_types.add("verification")
            elif "isola" in action_lower:
                current_action_type = "containment"
                action_types.add("containment")
            elif "blocca" in action_lower:
                current_action_type = "blocking"
                action_types.add("blocking")
            elif "rapporto" in action_lower:
                current_action_type = "reporting"
                action_types.add("reporting")
            else:
                current_action_type = "other"
                action_types.add("other")

            if "rapporto" in action_lower and "win" not in next_state and "end_success" not in next_state:
                self.operational_metrics["premature_reports"] += 1
                self.operational_metrics["health"] -= 10
                if verbose:
                    print(" ⚠️ Rilevato: Report Prematuro (-10 health)")

            if any(k in action_lower for k in ["analizza", "isola", "verifica", "cerca", "blocca", "scansione", "richiedi"]):
                self.operational_metrics["critical_actions_taken"] += 1
                self.operational_metrics["investigation_depth"] += 1

            if self._is_logical_action_sequence(prev_action, chosen_action):
                consecutive_logical += 1
                self.operational_metrics["consecutive_logical_actions"] = consecutive_logical
                if verbose:
                    print(f" ✅ Sequenza logica: {consecutive_logical} azioni consecutive")
            else:
                consecutive_logical = 0
                self.operational_metrics["consecutive_logical_actions"] = 0

            if chosen_cvss >= 7.0:
                high_cvss_count += 1
                is_after_investigation = prev_action_type in ["analysis", "verification"]
                is_emergency_first_step = (steps == 0 and current_action_type in ["containment", "blocking"])
                if is_after_investigation:
                    contextual_high_cvss_count += 1
                    if verbose:
                        print(f" ✅ CVSS alto contestualizzato (dopo analisi)")
                elif is_emergency_first_step:
                    contextual_high_cvss_count += 1
                    if verbose:
                        print(f" ✅ CVSS alto contestualizzato (risposta emergenza)")
                else:
                    self.operational_metrics["health"] -= 5
                    if verbose:
                        print(f" ⚠️ CVSS alto NON contestualizzato (-5 health)")

            if "end_fail" in next_state or "end_partial" in next_state:
                self.operational_metrics["dead_end_actions"] += 1
                self.operational_metrics["health"] -= 15
                if verbose:
                    print(" ⚠️ Rilevato: Vicolo Cieco (-15 health)")

            if "isola" in action_lower:
                self.operational_metrics["downtime_minutes"] += 15
                self.operational_metrics["action_costs"] += 2
            elif "scansione" in action_lower:
                self.operational_metrics["cpu_usage_percent"] += 10
                self.operational_metrics["action_costs"] += 1
            elif "blocca" in action_lower:
                self.operational_metrics["bandwidth_mb"] += 5
                self.operational_metrics["action_costs"] += 1
            elif "analizza" in action_lower:
                self.operational_metrics["cpu_usage_percent"] += 5
                self.operational_metrics["action_costs"] += 1
            elif "rapporto" in action_lower:
                self.operational_metrics["action_costs"] += 0.5

            self.operational_metrics["avg_cvss_score"] = (
                (self.operational_metrics["avg_cvss_score"] * steps + chosen_cvss) / (steps + 1)
            )
            self.operational_metrics["max_cvss_score"] = max(
                self.operational_metrics["max_cvss_score"], chosen_cvss
            )

            self.action_history.append(chosen_action)
            self.cvss_history.append(chosen_cvss)
            prev_action = chosen_action
            prev_action_type = current_action_type

            # Calcola punteggio parziale
            partial_result = {
                "status": "ongoing",
                "steps": steps,
                "history": history,
                "terminal": current,
                "health": self.operational_metrics["health"]
            }
            partial_score = self.calculate_partial_score(steps, scenario, self.operational_metrics, partial_result)
            self.operational_metrics["partial_scores"].append(partial_score)
            if verbose:
                print(f"\n✅ AZIONE SCELTA: {chosen_action}")
                print(f"📊 Punteggio parziale: {partial_score:.1f}/100")
                print(f"💓 Health: {self.operational_metrics['health']}/100")
                print(f"➡️ Prossimo stato: {next_state}")

            if current in history[-3:]:
                result = {"status": "loss", "steps": steps, "history": history, "terminal": "loop_detected"}
                score = self.calculate_final_score(steps, scenario, self.operational_metrics, result)
                if verbose:
                    print(f"\n❌ Punteggio finale: {score:.1f}/100")
                return {**result, "score": score, "metrics": self.operational_metrics, "agent": agent_name}

            current = next_state
            steps += 1

        total_actions = max(1, steps)
        self.operational_metrics["high_cvss_ratio"] = high_cvss_count / total_actions
        self.operational_metrics["contextual_high_cvss"] = contextual_high_cvss_count
        self.operational_metrics["action_variety"] = len(action_types) / max(1, total_actions)
        result = {"status": "loss", "steps": steps, "history": history, "terminal": "timeout"}
        score = self.calculate_final_score(steps, scenario, self.operational_metrics, result)
        if verbose:
            print(f"\n❌ Punteggio finale: {score:.1f}/100")
        return {**result, "score": score, "metrics": self.operational_metrics, "agent": agent_name}
    






# 8) Main
# --- ESECUZIONE DEL BENCHMARK ---
if __name__ == "__main__":
    benchmark = CybersecurityBenchmark(scenarios)
    print("📊 BENCHMARK DI CYBERSECURITY")
    print("Scegli lo scenario:")
    print("1. APT29 (spionaggio)")
    print("2. DDoS (disponibilità)")
    print("3. LockBit 3.0 Ransomware (disponibilità/integrità)")
    print("4. hospital_ransomware (disponibilità/integrità)")
    scenario_choice = input("Inserisci il numero dello scenario: ").strip()
    scenario_key = "apt29" if scenario_choice == "1" else "ddos" if scenario_choice == "2" else "lockbit3" if scenario_choice == "3" else "ransomware_hospital"

    agent_function, agent_name = choose_agent()

    result = benchmark.run_benchmark(
        scenario_key=scenario_key,
        agent_function=agent_function,
        agent_name=agent_name,
        max_steps=10,
        verbose=True
    )

    print("\n" + "="*80)
    print("📊 METRICHE OPERATIVE FINALI")
    print("="*80)
    for metric, value in result["metrics"].items():
        print(f"{metric.replace('_', ' ').title()}: {value}")
    print(f"\n🏆 PUNTEGGIO FINALE: {result['score']:.1f}/100")
    print(f"🤖 AI/AGENTE UTILIZZATO: {result['agent']}")
    print("="*80)

