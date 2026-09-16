rule TTP_XOR_QUAD_CurrentVersionRun_f5b9 {
  strings:
    $key_f5b9 = { a6 d6 [2] 82 d8 [2] a9 f4 [2] 87 d6 [2] 93 cd [2] 9c d7 [2] 82 ca [2] 80 cb [2] 9b cd [2] 87 ca [2] 9b e5 }

  condition:
    any of them
}