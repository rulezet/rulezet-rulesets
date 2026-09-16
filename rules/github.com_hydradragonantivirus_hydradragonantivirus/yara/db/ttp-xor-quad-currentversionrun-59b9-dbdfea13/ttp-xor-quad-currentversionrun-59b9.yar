rule TTP_XOR_QUAD_CurrentVersionRun_59b9 {
  strings:
    $key_59b9 = { 0a d6 [2] 2e d8 [2] 05 f4 [2] 2b d6 [2] 3f cd [2] 30 d7 [2] 2e ca [2] 2c cb [2] 37 cd [2] 2b ca [2] 37 e5 }

  condition:
    any of them
}