rule TTP_XOR_QUAD_CurrentVersionRun_7e8a {
  strings:
    $key_7e8a = { 2d e5 [2] 09 eb [2] 22 c7 [2] 0c e5 [2] 18 fe [2] 17 e4 [2] 09 f9 [2] 0b f8 [2] 10 fe [2] 0c f9 [2] 10 d6 }

  condition:
    any of them
}