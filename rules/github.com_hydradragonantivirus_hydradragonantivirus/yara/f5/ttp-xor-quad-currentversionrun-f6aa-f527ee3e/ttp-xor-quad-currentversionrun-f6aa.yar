rule TTP_XOR_QUAD_CurrentVersionRun_f6aa {
  strings:
    $key_f6aa = { a5 c5 [2] 81 cb [2] aa e7 [2] 84 c5 [2] 90 de [2] 9f c4 [2] 81 d9 [2] 83 d8 [2] 98 de [2] 84 d9 [2] 98 f6 }

  condition:
    any of them
}