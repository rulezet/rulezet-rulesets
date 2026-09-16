rule PEiD_01806_PseudoSigner_0_1__CodeSafe_2_0_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [CodeSafe 2.0] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9 }

  condition:
    $a
}