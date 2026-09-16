rule TTP_XOR_QUAD_CurrentVersionRun_56a6 {
  strings:
    $key_56a6 = { 05 c9 [2] 21 c7 [2] 0a eb [2] 24 c9 [2] 30 d2 [2] 3f c8 [2] 21 d5 [2] 23 d4 [2] 38 d2 [2] 24 d5 [2] 38 fa }

  condition:
    any of them
}