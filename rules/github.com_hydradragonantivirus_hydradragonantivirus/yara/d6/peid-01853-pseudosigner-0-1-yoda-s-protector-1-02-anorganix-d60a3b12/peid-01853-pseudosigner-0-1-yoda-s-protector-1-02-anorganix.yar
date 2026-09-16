rule PEiD_01853_PseudoSigner_0_1__Yoda_s_Protector_1_02_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Yoda's Protector 1.02] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { E8 03 00 00 00 EB 01 90 90 E9 }

  condition:
    $a
}