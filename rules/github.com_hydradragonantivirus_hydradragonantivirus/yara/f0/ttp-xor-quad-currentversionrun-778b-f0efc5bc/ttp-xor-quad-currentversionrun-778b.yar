rule TTP_XOR_QUAD_CurrentVersionRun_778b {
  strings:
    $key_778b = { 24 e4 [2] 00 ea [2] 2b c6 [2] 05 e4 [2] 11 ff [2] 1e e5 [2] 00 f8 [2] 02 f9 [2] 19 ff [2] 05 f8 [2] 19 d7 }

  condition:
    any of them
}