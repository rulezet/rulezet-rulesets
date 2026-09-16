rule TTP_XOR_QUAD_CurrentVersionRun_3ba6 {
  strings:
    $key_3ba6 = { 68 c9 [2] 4c c7 [2] 67 eb [2] 49 c9 [2] 5d d2 [2] 52 c8 [2] 4c d5 [2] 4e d4 [2] 55 d2 [2] 49 d5 [2] 55 fa }

  condition:
    any of them
}