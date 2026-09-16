rule TTP_XOR_QUAD_CurrentVersionRun_56b8 {
  strings:
    $key_56b8 = { 05 d7 [2] 21 d9 [2] 0a f5 [2] 24 d7 [2] 30 cc [2] 3f d6 [2] 21 cb [2] 23 ca [2] 38 cc [2] 24 cb [2] 38 e4 }

  condition:
    any of them
}