rule TTP_XOR_QUAD_CurrentVersionRun_1aa4 {
  strings:
    $key_1aa4 = { 49 cb [2] 6d c5 [2] 46 e9 [2] 68 cb [2] 7c d0 [2] 73 ca [2] 6d d7 [2] 6f d6 [2] 74 d0 [2] 68 d7 [2] 74 f8 }

  condition:
    any of them
}