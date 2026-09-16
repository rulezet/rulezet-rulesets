rule TTP_XOR_QUAD_CurrentVersionRun_b0b7 {
  strings:
    $key_b0b7 = { e3 d8 [2] c7 d6 [2] ec fa [2] c2 d8 [2] d6 c3 [2] d9 d9 [2] c7 c4 [2] c5 c5 [2] de c3 [2] c2 c4 [2] de eb }

  condition:
    any of them
}