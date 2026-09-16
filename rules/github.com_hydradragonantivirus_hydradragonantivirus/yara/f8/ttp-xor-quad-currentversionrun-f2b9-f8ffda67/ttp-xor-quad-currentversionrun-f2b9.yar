rule TTP_XOR_QUAD_CurrentVersionRun_f2b9 {
  strings:
    $key_f2b9 = { a1 d6 [2] 85 d8 [2] ae f4 [2] 80 d6 [2] 94 cd [2] 9b d7 [2] 85 ca [2] 87 cb [2] 9c cd [2] 80 ca [2] 9c e5 }

  condition:
    any of them
}