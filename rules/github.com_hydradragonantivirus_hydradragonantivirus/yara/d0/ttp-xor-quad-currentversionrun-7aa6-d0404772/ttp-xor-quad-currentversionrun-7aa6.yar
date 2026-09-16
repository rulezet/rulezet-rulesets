rule TTP_XOR_QUAD_CurrentVersionRun_7aa6 {
  strings:
    $key_7aa6 = { 29 c9 [2] 0d c7 [2] 26 eb [2] 08 c9 [2] 1c d2 [2] 13 c8 [2] 0d d5 [2] 0f d4 [2] 14 d2 [2] 08 d5 [2] 14 fa }

  condition:
    any of them
}