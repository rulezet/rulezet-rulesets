rule TTP_XOR_QUAD_CurrentVersionRun_578b {
  strings:
    $key_578b = { 04 e4 [2] 20 ea [2] 0b c6 [2] 25 e4 [2] 31 ff [2] 3e e5 [2] 20 f8 [2] 22 f9 [2] 39 ff [2] 25 f8 [2] 39 d7 }

  condition:
    any of them
}