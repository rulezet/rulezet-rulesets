rule TTP_XOR_QUAD_CurrentVersionRun_79b9 {
  strings:
    $key_79b9 = { 2a d6 [2] 0e d8 [2] 25 f4 [2] 0b d6 [2] 1f cd [2] 10 d7 [2] 0e ca [2] 0c cb [2] 17 cd [2] 0b ca [2] 17 e5 }

  condition:
    any of them
}