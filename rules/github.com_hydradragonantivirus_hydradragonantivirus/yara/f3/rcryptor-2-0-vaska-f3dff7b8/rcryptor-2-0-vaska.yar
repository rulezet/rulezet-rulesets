import "pe"
rule RCryptor_2_0____Vaska {
  strings:
    $a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }

  condition:
    $a0 at pe.entry_point
}