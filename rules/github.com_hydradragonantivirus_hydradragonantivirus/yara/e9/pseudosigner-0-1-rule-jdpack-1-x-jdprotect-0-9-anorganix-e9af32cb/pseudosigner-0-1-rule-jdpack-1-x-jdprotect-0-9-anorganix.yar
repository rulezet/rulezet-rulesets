import "pe"
rule __PseudoSigner_0_1_rule__JDPack_1_x___JDProtect_0_9______Anorganix {
  strings:
    $a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9 }

  condition:
    $a0 at pe.entry_point
}