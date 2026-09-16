rule TTP_XOR_QUAD_CurrentVersionRun_4da6 {
  strings:
    $key_4da6 = { 1e c9 [2] 3a c7 [2] 11 eb [2] 3f c9 [2] 2b d2 [2] 24 c8 [2] 3a d5 [2] 38 d4 [2] 23 d2 [2] 3f d5 [2] 23 fa }

  condition:
    any of them
}