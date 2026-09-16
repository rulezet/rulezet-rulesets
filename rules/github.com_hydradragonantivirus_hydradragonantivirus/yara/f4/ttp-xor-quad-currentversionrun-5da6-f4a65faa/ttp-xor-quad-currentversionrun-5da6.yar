rule TTP_XOR_QUAD_CurrentVersionRun_5da6 {
  strings:
    $key_5da6 = { 0e c9 [2] 2a c7 [2] 01 eb [2] 2f c9 [2] 3b d2 [2] 34 c8 [2] 2a d5 [2] 28 d4 [2] 33 d2 [2] 2f d5 [2] 33 fa }

  condition:
    any of them
}