rule TTP_XOR_QUAD_CurrentVersionRun_248b {
  strings:
    $key_248b = { 77 e4 [2] 53 ea [2] 78 c6 [2] 56 e4 [2] 42 ff [2] 4d e5 [2] 53 f8 [2] 51 f9 [2] 4a ff [2] 56 f8 [2] 4a d7 }

  condition:
    any of them
}