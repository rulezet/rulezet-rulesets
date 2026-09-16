rule TTP_XOR_QUAD_CurrentVersionRun_49a6 {
  strings:
    $key_49a6 = { 1a c9 [2] 3e c7 [2] 15 eb [2] 3b c9 [2] 2f d2 [2] 20 c8 [2] 3e d5 [2] 3c d4 [2] 27 d2 [2] 3b d5 [2] 27 fa }

  condition:
    any of them
}