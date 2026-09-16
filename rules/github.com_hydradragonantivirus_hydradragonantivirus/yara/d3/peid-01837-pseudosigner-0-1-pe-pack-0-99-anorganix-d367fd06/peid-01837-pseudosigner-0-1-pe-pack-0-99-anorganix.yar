rule PEiD_01837_PseudoSigner_0_1__PE_Pack_0_99_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [PE Pack 0.99] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9 }

  condition:
    $a
}