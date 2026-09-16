rule TTP_XOR_QUAD_CurrentVersionRun_57aa {
  strings:
    $key_57aa = { 04 c5 [2] 20 cb [2] 0b e7 [2] 25 c5 [2] 31 de [2] 3e c4 [2] 20 d9 [2] 22 d8 [2] 39 de [2] 25 d9 [2] 39 f6 }

  condition:
    any of them
}