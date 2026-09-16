rule TTP_XOR_QUAD_CurrentVersionRun_048b {
  strings:
    $key_048b = { 57 e4 [2] 73 ea [2] 58 c6 [2] 76 e4 [2] 62 ff [2] 6d e5 [2] 73 f8 [2] 71 f9 [2] 6a ff [2] 76 f8 [2] 6a d7 }

  condition:
    any of them
}