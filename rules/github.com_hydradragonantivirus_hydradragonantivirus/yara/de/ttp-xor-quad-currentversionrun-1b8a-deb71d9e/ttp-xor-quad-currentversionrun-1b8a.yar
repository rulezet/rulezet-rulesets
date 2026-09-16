rule TTP_XOR_QUAD_CurrentVersionRun_1b8a {
  strings:
    $key_1b8a = { 48 e5 [2] 6c eb [2] 47 c7 [2] 69 e5 [2] 7d fe [2] 72 e4 [2] 6c f9 [2] 6e f8 [2] 75 fe [2] 69 f9 [2] 75 d6 }

  condition:
    any of them
}