rule TTP_XOR_QUAD_CurrentVersionRun_7fa6 {
  strings:
    $key_7fa6 = { 2c c9 [2] 08 c7 [2] 23 eb [2] 0d c9 [2] 19 d2 [2] 16 c8 [2] 08 d5 [2] 0a d4 [2] 11 d2 [2] 0d d5 [2] 11 fa }

  condition:
    any of them
}