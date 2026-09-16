rule TTP_XOR_QUAD_CurrentVersionRun_2585 {
  strings:
    $key_2585 = { 76 ea [2] 52 e4 [2] 79 c8 [2] 57 ea [2] 43 f1 [2] 4c eb [2] 52 f6 [2] 50 f7 [2] 4b f1 [2] 57 f6 [2] 4b d9 }

  condition:
    any of them
}