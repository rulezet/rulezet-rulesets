rule TTP_XOR_QUAD_CurrentVersionRun_1d8b {
  strings:
    $key_1d8b = { 4e e4 [2] 6a ea [2] 41 c6 [2] 6f e4 [2] 7b ff [2] 74 e5 [2] 6a f8 [2] 68 f9 [2] 73 ff [2] 6f f8 [2] 73 d7 }

  condition:
    any of them
}