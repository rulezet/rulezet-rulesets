rule TTP_XOR_QUAD_CurrentVersionRun_1f8b {
  strings:
    $key_1f8b = { 4c e4 [2] 68 ea [2] 43 c6 [2] 6d e4 [2] 79 ff [2] 76 e5 [2] 68 f8 [2] 6a f9 [2] 71 ff [2] 6d f8 [2] 71 d7 }

  condition:
    any of them
}