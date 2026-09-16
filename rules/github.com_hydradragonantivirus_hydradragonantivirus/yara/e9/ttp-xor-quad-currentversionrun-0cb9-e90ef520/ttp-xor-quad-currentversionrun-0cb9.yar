rule TTP_XOR_QUAD_CurrentVersionRun_0cb9 {
  strings:
    $key_0cb9 = { 5f d6 [2] 7b d8 [2] 50 f4 [2] 7e d6 [2] 6a cd [2] 65 d7 [2] 7b ca [2] 79 cb [2] 62 cd [2] 7e ca [2] 62 e5 }

  condition:
    any of them
}