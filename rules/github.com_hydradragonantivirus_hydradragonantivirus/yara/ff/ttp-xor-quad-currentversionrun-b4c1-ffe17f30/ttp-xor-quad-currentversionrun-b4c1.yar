rule TTP_XOR_QUAD_CurrentVersionRun_b4c1 {
  strings:
    $key_b4c1 = { e7 ae [2] c3 a0 [2] e8 8c [2] c6 ae [2] d2 b5 [2] dd af [2] c3 b2 [2] c1 b3 [2] da b5 [2] c6 b2 [2] da 9d }

  condition:
    any of them
}