rule TTP_XOR_QUAD_CurrentVersionRun_2485 {
  strings:
    $key_2485 = { 77 ea [2] 53 e4 [2] 78 c8 [2] 56 ea [2] 42 f1 [2] 4d eb [2] 53 f6 [2] 51 f7 [2] 4a f1 [2] 56 f6 [2] 4a d9 }

  condition:
    any of them
}