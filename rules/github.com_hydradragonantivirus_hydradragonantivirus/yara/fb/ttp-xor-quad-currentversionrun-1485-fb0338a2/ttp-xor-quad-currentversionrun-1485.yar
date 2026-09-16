rule TTP_XOR_QUAD_CurrentVersionRun_1485 {
  strings:
    $key_1485 = { 47 ea [2] 63 e4 [2] 48 c8 [2] 66 ea [2] 72 f1 [2] 7d eb [2] 63 f6 [2] 61 f7 [2] 7a f1 [2] 66 f6 [2] 7a d9 }

  condition:
    any of them
}