rule TTP_XOR_QUAD_CurrentVersionRun_018b {
  strings:
    $key_018b = { 52 e4 [2] 76 ea [2] 5d c6 [2] 73 e4 [2] 67 ff [2] 68 e5 [2] 76 f8 [2] 74 f9 [2] 6f ff [2] 73 f8 [2] 6f d7 }

  condition:
    any of them
}