rule TTP_XOR_QUAD_CurrentVersionRun_76b8 {
  strings:
    $key_76b8 = { 25 d7 [2] 01 d9 [2] 2a f5 [2] 04 d7 [2] 10 cc [2] 1f d6 [2] 01 cb [2] 03 ca [2] 18 cc [2] 04 cb [2] 18 e4 }

  condition:
    any of them
}