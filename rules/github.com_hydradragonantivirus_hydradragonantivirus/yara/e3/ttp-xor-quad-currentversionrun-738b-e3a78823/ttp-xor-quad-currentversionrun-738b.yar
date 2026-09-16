rule TTP_XOR_QUAD_CurrentVersionRun_738b {
  strings:
    $key_738b = { 20 e4 [2] 04 ea [2] 2f c6 [2] 01 e4 [2] 15 ff [2] 1a e5 [2] 04 f8 [2] 06 f9 [2] 1d ff [2] 01 f8 [2] 1d d7 }

  condition:
    any of them
}