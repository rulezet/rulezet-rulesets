rule TTP_XOR_QUAD_CurrentVersionRun_e9b9 {
  strings:
    $key_e9b9 = { ba d6 [2] 9e d8 [2] b5 f4 [2] 9b d6 [2] 8f cd [2] 80 d7 [2] 9e ca [2] 9c cb [2] 87 cd [2] 9b ca [2] 87 e5 }

  condition:
    any of them
}