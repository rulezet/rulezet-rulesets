rule TTP_XOR_QUAD_CurrentVersionRun_e9a6 {
  strings:
    $key_e9a6 = { ba c9 [2] 9e c7 [2] b5 eb [2] 9b c9 [2] 8f d2 [2] 80 c8 [2] 9e d5 [2] 9c d4 [2] 87 d2 [2] 9b d5 [2] 87 fa }

  condition:
    any of them
}