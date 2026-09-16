rule TTP_XOR_QUAD_CurrentVersionRun_0c8a {
  strings:
    $key_0c8a = { 5f e5 [2] 7b eb [2] 50 c7 [2] 7e e5 [2] 6a fe [2] 65 e4 [2] 7b f9 [2] 79 f8 [2] 62 fe [2] 7e f9 [2] 62 d6 }

  condition:
    any of them
}