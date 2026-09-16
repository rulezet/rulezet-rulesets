rule TTP_XOR_QUAD_CurrentVersionRun_e5b9 {
  strings:
    $key_e5b9 = { b6 d6 [2] 92 d8 [2] b9 f4 [2] 97 d6 [2] 83 cd [2] 8c d7 [2] 92 ca [2] 90 cb [2] 8b cd [2] 97 ca [2] 8b e5 }

  condition:
    any of them
}