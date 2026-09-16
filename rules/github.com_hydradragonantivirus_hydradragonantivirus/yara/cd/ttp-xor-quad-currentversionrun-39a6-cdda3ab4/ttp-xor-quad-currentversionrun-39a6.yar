rule TTP_XOR_QUAD_CurrentVersionRun_39a6 {
  strings:
    $key_39a6 = { 6a c9 [2] 4e c7 [2] 65 eb [2] 4b c9 [2] 5f d2 [2] 50 c8 [2] 4e d5 [2] 4c d4 [2] 57 d2 [2] 4b d5 [2] 57 fa }

  condition:
    any of them
}