rule TTP_XOR_QUAD_CurrentVersionRun_ec8a {
  strings:
    $key_ec8a = { bf e5 [2] 9b eb [2] b0 c7 [2] 9e e5 [2] 8a fe [2] 85 e4 [2] 9b f9 [2] 99 f8 [2] 82 fe [2] 9e f9 [2] 82 d6 }

  condition:
    any of them
}