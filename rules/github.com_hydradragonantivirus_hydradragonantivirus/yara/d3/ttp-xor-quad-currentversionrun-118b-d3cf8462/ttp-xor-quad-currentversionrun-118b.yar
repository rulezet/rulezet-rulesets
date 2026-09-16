rule TTP_XOR_QUAD_CurrentVersionRun_118b {
  strings:
    $key_118b = { 42 e4 [2] 66 ea [2] 4d c6 [2] 63 e4 [2] 77 ff [2] 78 e5 [2] 66 f8 [2] 64 f9 [2] 7f ff [2] 63 f8 [2] 7f d7 }

  condition:
    any of them
}