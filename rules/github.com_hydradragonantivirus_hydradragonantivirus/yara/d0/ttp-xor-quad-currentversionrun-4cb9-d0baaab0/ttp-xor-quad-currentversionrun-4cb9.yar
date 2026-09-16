rule TTP_XOR_QUAD_CurrentVersionRun_4cb9 {
  strings:
    $key_4cb9 = { 1f d6 [2] 3b d8 [2] 10 f4 [2] 3e d6 [2] 2a cd [2] 25 d7 [2] 3b ca [2] 39 cb [2] 22 cd [2] 3e ca [2] 22 e5 }

  condition:
    any of them
}