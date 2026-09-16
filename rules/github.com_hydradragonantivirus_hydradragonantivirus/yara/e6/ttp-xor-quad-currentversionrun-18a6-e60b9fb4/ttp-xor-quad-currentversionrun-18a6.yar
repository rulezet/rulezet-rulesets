rule TTP_XOR_QUAD_CurrentVersionRun_18a6 {
  strings:
    $key_18a6 = { 4b c9 [2] 6f c7 [2] 44 eb [2] 6a c9 [2] 7e d2 [2] 71 c8 [2] 6f d5 [2] 6d d4 [2] 76 d2 [2] 6a d5 [2] 76 fa }

  condition:
    any of them
}