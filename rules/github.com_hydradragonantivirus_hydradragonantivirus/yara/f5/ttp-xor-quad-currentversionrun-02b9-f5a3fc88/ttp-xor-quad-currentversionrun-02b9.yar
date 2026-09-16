rule TTP_XOR_QUAD_CurrentVersionRun_02b9 {
  strings:
    $key_02b9 = { 51 d6 [2] 75 d8 [2] 5e f4 [2] 70 d6 [2] 64 cd [2] 6b d7 [2] 75 ca [2] 77 cb [2] 6c cd [2] 70 ca [2] 6c e5 }

  condition:
    any of them
}