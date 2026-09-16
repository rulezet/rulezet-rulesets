rule TTP_XOR_QUAD_CurrentVersionRun_0685 {
  strings:
    $key_0685 = { 55 ea [2] 71 e4 [2] 5a c8 [2] 74 ea [2] 60 f1 [2] 6f eb [2] 71 f6 [2] 73 f7 [2] 68 f1 [2] 74 f6 [2] 68 d9 }

  condition:
    any of them
}