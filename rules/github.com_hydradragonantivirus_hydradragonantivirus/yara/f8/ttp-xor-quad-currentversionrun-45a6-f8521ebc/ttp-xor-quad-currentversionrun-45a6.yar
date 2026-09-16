rule TTP_XOR_QUAD_CurrentVersionRun_45a6 {
  strings:
    $key_45a6 = { 16 c9 [2] 32 c7 [2] 19 eb [2] 37 c9 [2] 23 d2 [2] 2c c8 [2] 32 d5 [2] 30 d4 [2] 2b d2 [2] 37 d5 [2] 2b fa }

  condition:
    any of them
}