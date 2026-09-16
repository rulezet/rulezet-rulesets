rule TTP_XOR_QUAD_CurrentVersionRun_b1f3 {
  strings:
    $key_b1f3 = { e2 9c [2] c6 92 [2] ed be [2] c3 9c [2] d7 87 [2] d8 9d [2] c6 80 [2] c4 81 [2] df 87 [2] c3 80 [2] df af }

  condition:
    any of them
}