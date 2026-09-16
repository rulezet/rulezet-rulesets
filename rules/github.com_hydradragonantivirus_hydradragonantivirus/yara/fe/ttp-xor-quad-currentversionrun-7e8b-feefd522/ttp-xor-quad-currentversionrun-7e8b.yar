rule TTP_XOR_QUAD_CurrentVersionRun_7e8b {
  strings:
    $key_7e8b = { 2d e4 [2] 09 ea [2] 22 c6 [2] 0c e4 [2] 18 ff [2] 17 e5 [2] 09 f8 [2] 0b f9 [2] 10 ff [2] 0c f8 [2] 10 d7 }

  condition:
    any of them
}