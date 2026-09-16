rule PEiD_01865_PseudoSigner_0_2__CodeSafe_2_0__ {
  meta:
    description = "[PseudoSigner 0.2 [CodeSafe 2.0]]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 }

  condition:
    $a
}