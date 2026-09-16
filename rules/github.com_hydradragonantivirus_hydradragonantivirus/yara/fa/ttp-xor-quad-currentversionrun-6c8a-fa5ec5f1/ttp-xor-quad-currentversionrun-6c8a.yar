rule TTP_XOR_QUAD_CurrentVersionRun_6c8a {
  strings:
    $key_6c8a = { 3f e5 [2] 1b eb [2] 30 c7 [2] 1e e5 [2] 0a fe [2] 05 e4 [2] 1b f9 [2] 19 f8 [2] 02 fe [2] 1e f9 [2] 02 d6 }

  condition:
    any of them
}