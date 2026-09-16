rule TTP_XOR_QUAD_CurrentVersionRun_b463 {
  strings:
    $key_b463 = { e7 0c [2] c3 02 [2] e8 2e [2] c6 0c [2] d2 17 [2] dd 0d [2] c3 10 [2] c1 11 [2] da 17 [2] c6 10 [2] da 3f }

  condition:
    any of them
}