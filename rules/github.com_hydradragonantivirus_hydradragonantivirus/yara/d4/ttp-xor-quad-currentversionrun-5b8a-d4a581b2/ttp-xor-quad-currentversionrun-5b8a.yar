rule TTP_XOR_QUAD_CurrentVersionRun_5b8a {
  strings:
    $key_5b8a = { 08 e5 [2] 2c eb [2] 07 c7 [2] 29 e5 [2] 3d fe [2] 32 e4 [2] 2c f9 [2] 2e f8 [2] 35 fe [2] 29 f9 [2] 35 d6 }

  condition:
    any of them
}