rule TTP_XOR_QUAD_CurrentVersionRun_6b8a {
  strings:
    $key_6b8a = { 38 e5 [2] 1c eb [2] 37 c7 [2] 19 e5 [2] 0d fe [2] 02 e4 [2] 1c f9 [2] 1e f8 [2] 05 fe [2] 19 f9 [2] 05 d6 }

  condition:
    any of them
}