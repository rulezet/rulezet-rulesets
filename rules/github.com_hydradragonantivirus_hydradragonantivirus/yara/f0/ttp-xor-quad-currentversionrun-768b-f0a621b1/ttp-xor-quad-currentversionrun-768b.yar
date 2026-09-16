rule TTP_XOR_QUAD_CurrentVersionRun_768b {
  strings:
    $key_768b = { 25 e4 [2] 01 ea [2] 2a c6 [2] 04 e4 [2] 10 ff [2] 1f e5 [2] 01 f8 [2] 03 f9 [2] 18 ff [2] 04 f8 [2] 18 d7 }

  condition:
    any of them
}