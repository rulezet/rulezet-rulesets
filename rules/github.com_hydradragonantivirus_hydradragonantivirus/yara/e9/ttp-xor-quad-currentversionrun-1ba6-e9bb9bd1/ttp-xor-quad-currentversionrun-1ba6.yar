rule TTP_XOR_QUAD_CurrentVersionRun_1ba6 {
  strings:
    $key_1ba6 = { 48 c9 [2] 6c c7 [2] 47 eb [2] 69 c9 [2] 7d d2 [2] 72 c8 [2] 6c d5 [2] 6e d4 [2] 75 d2 [2] 69 d5 [2] 75 fa }

  condition:
    any of them
}