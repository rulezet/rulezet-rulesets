rule TTP_XOR_QUAD_CurrentVersionRun_73a6 {
  strings:
    $key_73a6 = { 20 c9 [2] 04 c7 [2] 2f eb [2] 01 c9 [2] 15 d2 [2] 1a c8 [2] 04 d5 [2] 06 d4 [2] 1d d2 [2] 01 d5 [2] 1d fa }

  condition:
    any of them
}