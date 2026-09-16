rule TTP_XOR_QUAD_CurrentVersionRun_06aa {
  strings:
    $key_06aa = { 55 c5 [2] 71 cb [2] 5a e7 [2] 74 c5 [2] 60 de [2] 6f c4 [2] 71 d9 [2] 73 d8 [2] 68 de [2] 74 d9 [2] 68 f6 }

  condition:
    any of them
}