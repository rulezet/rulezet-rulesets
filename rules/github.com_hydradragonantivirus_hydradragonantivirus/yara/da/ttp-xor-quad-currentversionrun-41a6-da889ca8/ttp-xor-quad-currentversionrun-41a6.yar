rule TTP_XOR_QUAD_CurrentVersionRun_41a6 {
  strings:
    $key_41a6 = { 12 c9 [2] 36 c7 [2] 1d eb [2] 33 c9 [2] 27 d2 [2] 28 c8 [2] 36 d5 [2] 34 d4 [2] 2f d2 [2] 33 d5 [2] 2f fa }

  condition:
    any of them
}