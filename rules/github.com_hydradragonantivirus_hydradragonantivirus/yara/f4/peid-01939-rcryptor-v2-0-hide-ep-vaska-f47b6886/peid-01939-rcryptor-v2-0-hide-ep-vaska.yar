rule PEiD_01939_RCryptor_v2_0__Hide_EP______Vaska_ {
  meta:
    description = "[RCryptor v2.0 (Hide EP) --> Vaska]"
    ep_only     = "true"

  strings:
    $a = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }

  condition:
    $a
}