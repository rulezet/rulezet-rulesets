rule PEiD_01804_PseudoSigner_0_1__CD_Cops_II_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [CD-Cops II] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9 }

  condition:
    $a
}