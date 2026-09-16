rule TTP_XOR_QUAD_CurrentVersionRun_6085 {
  strings:
    $key_6085 = { 33 ea [2] 17 e4 [2] 3c c8 [2] 12 ea [2] 06 f1 [2] 09 eb [2] 17 f6 [2] 15 f7 [2] 0e f1 [2] 12 f6 [2] 0e d9 }

  condition:
    any of them
}