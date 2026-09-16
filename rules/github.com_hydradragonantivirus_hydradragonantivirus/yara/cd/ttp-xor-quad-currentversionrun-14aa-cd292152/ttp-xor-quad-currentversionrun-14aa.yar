rule TTP_XOR_QUAD_CurrentVersionRun_14aa {
  strings:
    $key_14aa = { 47 c5 [2] 63 cb [2] 48 e7 [2] 66 c5 [2] 72 de [2] 7d c4 [2] 63 d9 [2] 61 d8 [2] 7a de [2] 66 d9 [2] 7a f6 }

  condition:
    any of them
}