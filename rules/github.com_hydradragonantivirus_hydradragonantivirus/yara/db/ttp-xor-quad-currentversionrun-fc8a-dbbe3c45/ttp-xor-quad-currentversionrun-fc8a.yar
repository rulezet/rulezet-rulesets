rule TTP_XOR_QUAD_CurrentVersionRun_fc8a {
  strings:
    $key_fc8a = { af e5 [2] 8b eb [2] a0 c7 [2] 8e e5 [2] 9a fe [2] 95 e4 [2] 8b f9 [2] 89 f8 [2] 92 fe [2] 8e f9 [2] 92 d6 }

  condition:
    any of them
}