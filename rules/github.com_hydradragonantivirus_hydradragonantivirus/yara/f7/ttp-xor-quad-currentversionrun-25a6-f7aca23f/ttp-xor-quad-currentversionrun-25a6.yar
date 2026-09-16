rule TTP_XOR_QUAD_CurrentVersionRun_25a6 {
  strings:
    $key_25a6 = { 76 c9 [2] 52 c7 [2] 79 eb [2] 57 c9 [2] 43 d2 [2] 4c c8 [2] 52 d5 [2] 50 d4 [2] 4b d2 [2] 57 d5 [2] 4b fa }

  condition:
    any of them
}