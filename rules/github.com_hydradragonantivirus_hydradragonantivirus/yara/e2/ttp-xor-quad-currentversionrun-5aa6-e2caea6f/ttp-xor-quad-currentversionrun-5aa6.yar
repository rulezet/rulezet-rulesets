rule TTP_XOR_QUAD_CurrentVersionRun_5aa6 {
  strings:
    $key_5aa6 = { 09 c9 [2] 2d c7 [2] 06 eb [2] 28 c9 [2] 3c d2 [2] 33 c8 [2] 2d d5 [2] 2f d4 [2] 34 d2 [2] 28 d5 [2] 34 fa }

  condition:
    any of them
}