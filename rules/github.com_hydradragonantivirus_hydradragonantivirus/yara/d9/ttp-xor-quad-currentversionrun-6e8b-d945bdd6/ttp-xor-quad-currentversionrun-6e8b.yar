rule TTP_XOR_QUAD_CurrentVersionRun_6e8b {
  strings:
    $key_6e8b = { 3d e4 [2] 19 ea [2] 32 c6 [2] 1c e4 [2] 08 ff [2] 07 e5 [2] 19 f8 [2] 1b f9 [2] 00 ff [2] 1c f8 [2] 00 d7 }

  condition:
    any of them
}