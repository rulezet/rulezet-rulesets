rule TTP_XOR_QUAD_CurrentVersionRun_01a5 {
  strings:
    $key_01a5 = { 52 ca [2] 76 c4 [2] 5d e8 [2] 73 ca [2] 67 d1 [2] 68 cb [2] 76 d6 [2] 74 d7 [2] 6f d1 [2] 73 d6 [2] 6f f9 }

  condition:
    any of them
}