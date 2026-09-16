rule TTP_XOR_QUAD_CurrentVersionRun_7685 {
  strings:
    $key_7685 = { 25 ea [2] 01 e4 [2] 2a c8 [2] 04 ea [2] 10 f1 [2] 1f eb [2] 01 f6 [2] 03 f7 [2] 18 f1 [2] 04 f6 [2] 18 d9 }

  condition:
    any of them
}