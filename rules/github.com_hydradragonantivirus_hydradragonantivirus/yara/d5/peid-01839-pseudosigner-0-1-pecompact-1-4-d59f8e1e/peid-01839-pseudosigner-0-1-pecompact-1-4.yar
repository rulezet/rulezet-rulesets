rule PEiD_01839_PseudoSigner_0_1__PECompact_1_4___ {
  meta:
    description = "[PseudoSigner 0.1 [PECompact 1.4+]]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

  condition:
    $a
}