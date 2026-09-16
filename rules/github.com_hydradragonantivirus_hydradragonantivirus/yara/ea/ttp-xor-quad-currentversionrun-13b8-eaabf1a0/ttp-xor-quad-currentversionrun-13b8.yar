rule TTP_XOR_QUAD_CurrentVersionRun_13b8 {
  strings:
    $key_13b8 = { 40 d7 [2] 64 d9 [2] 4f f5 [2] 61 d7 [2] 75 cc [2] 7a d6 [2] 64 cb [2] 66 ca [2] 7d cc [2] 61 cb [2] 7d e4 }

  condition:
    any of them
}