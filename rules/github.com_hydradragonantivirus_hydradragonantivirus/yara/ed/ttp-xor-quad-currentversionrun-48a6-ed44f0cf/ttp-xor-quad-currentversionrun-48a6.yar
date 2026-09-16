rule TTP_XOR_QUAD_CurrentVersionRun_48a6 {
  strings:
    $key_48a6 = { 1b c9 [2] 3f c7 [2] 14 eb [2] 3a c9 [2] 2e d2 [2] 21 c8 [2] 3f d5 [2] 3d d4 [2] 26 d2 [2] 3a d5 [2] 26 fa }

  condition:
    any of them
}