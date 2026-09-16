rule TTP_XOR_QUAD_CurrentVersionRun_4b8a {
  strings:
    $key_4b8a = { 18 e5 [2] 3c eb [2] 17 c7 [2] 39 e5 [2] 2d fe [2] 22 e4 [2] 3c f9 [2] 3e f8 [2] 25 fe [2] 39 f9 [2] 25 d6 }

  condition:
    any of them
}