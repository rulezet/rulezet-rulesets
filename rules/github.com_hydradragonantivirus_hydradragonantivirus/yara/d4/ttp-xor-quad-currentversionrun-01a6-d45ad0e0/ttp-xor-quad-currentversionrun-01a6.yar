rule TTP_XOR_QUAD_CurrentVersionRun_01a6 {
  strings:
    $key_01a6 = { 52 c9 [2] 76 c7 [2] 5d eb [2] 73 c9 [2] 67 d2 [2] 68 c8 [2] 76 d5 [2] 74 d4 [2] 6f d2 [2] 73 d5 [2] 6f fa }

  condition:
    any of them
}