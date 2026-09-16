rule TTP_XOR_QUAD_CurrentVersionRun_3ea6 {
  strings:
    $key_3ea6 = { 6d c9 [2] 49 c7 [2] 62 eb [2] 4c c9 [2] 58 d2 [2] 57 c8 [2] 49 d5 [2] 4b d4 [2] 50 d2 [2] 4c d5 [2] 50 fa }

  condition:
    any of them
}