rule PEiD_01820_PseudoSigner_0_1__MEW_11_SE_1_0_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [MEW 11 SE 1.0] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }

  condition:
    $a
}