rule TTP_XOR_QUAD_CurrentVersionRun_0484 {
  strings:
    $key_0484 = { 57 eb [2] 73 e5 [2] 58 c9 [2] 76 eb [2] 62 f0 [2] 6d ea [2] 73 f7 [2] 71 f6 [2] 6a f0 [2] 76 f7 [2] 6a d8 }

  condition:
    any of them
}