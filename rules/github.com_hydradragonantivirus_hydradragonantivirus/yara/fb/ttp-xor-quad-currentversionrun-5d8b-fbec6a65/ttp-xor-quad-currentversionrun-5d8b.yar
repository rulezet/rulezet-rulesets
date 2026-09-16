rule TTP_XOR_QUAD_CurrentVersionRun_5d8b {
  strings:
    $key_5d8b = { 0e e4 [2] 2a ea [2] 01 c6 [2] 2f e4 [2] 3b ff [2] 34 e5 [2] 2a f8 [2] 28 f9 [2] 33 ff [2] 2f f8 [2] 33 d7 }

  condition:
    any of them
}