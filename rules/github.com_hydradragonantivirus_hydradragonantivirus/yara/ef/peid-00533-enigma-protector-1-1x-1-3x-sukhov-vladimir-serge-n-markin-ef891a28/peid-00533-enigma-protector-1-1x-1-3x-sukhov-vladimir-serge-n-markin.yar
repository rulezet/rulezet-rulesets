rule PEiD_00533_Enigma_Protector_1_1X_1_3X____Sukhov_Vladimir___Serge_N__Markin_ {
  meta:
    description = "[Enigma Protector 1.1X-1.3X -> Sukhov Vladimir & Serge N. Markin]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }

  condition:
    $a
}