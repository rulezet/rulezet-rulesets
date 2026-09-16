rule TTP_XOR_QUAD_CurrentVersionRun_5585 {
  strings:
    $key_5585 = { 06 ea [2] 22 e4 [2] 09 c8 [2] 27 ea [2] 33 f1 [2] 3c eb [2] 22 f6 [2] 20 f7 [2] 3b f1 [2] 27 f6 [2] 3b d9 }

  condition:
    any of them
}