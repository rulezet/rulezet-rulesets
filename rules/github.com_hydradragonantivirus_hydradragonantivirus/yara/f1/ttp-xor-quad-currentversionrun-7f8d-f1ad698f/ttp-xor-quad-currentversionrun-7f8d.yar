rule TTP_XOR_QUAD_CurrentVersionRun_7f8d {
  strings:
    $key_7f8d = { 2c e2 [2] 08 ec [2] 23 c0 [2] 0d e2 [2] 19 f9 [2] 16 e3 [2] 08 fe [2] 0a ff [2] 11 f9 [2] 0d fe [2] 11 d1 }

  condition:
    any of them
}