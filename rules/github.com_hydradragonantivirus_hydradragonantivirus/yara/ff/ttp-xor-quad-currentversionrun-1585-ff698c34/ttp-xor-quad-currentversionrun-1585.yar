rule TTP_XOR_QUAD_CurrentVersionRun_1585 {
  strings:
    $key_1585 = { 46 ea [2] 62 e4 [2] 49 c8 [2] 67 ea [2] 73 f1 [2] 7c eb [2] 62 f6 [2] 60 f7 [2] 7b f1 [2] 67 f6 [2] 7b d9 }

  condition:
    any of them
}