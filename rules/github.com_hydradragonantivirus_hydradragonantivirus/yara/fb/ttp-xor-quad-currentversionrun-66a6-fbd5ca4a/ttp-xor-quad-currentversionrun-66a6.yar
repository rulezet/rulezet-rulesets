rule TTP_XOR_QUAD_CurrentVersionRun_66a6 {
  strings:
    $key_66a6 = { 35 c9 [2] 11 c7 [2] 3a eb [2] 14 c9 [2] 00 d2 [2] 0f c8 [2] 11 d5 [2] 13 d4 [2] 08 d2 [2] 14 d5 [2] 08 fa }

  condition:
    any of them
}