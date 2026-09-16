rule TTP_XOR_QUAD_CurrentVersionRun_7d8b {
  strings:
    $key_7d8b = { 2e e4 [2] 0a ea [2] 21 c6 [2] 0f e4 [2] 1b ff [2] 14 e5 [2] 0a f8 [2] 08 f9 [2] 13 ff [2] 0f f8 [2] 13 d7 }

  condition:
    any of them
}