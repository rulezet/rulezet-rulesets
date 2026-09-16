rule TTP_XOR_QUAD_CurrentVersionRun_17b9 {
  strings:
    $key_17b9 = { 44 d6 [2] 60 d8 [2] 4b f4 [2] 65 d6 [2] 71 cd [2] 7e d7 [2] 60 ca [2] 62 cb [2] 79 cd [2] 65 ca [2] 79 e5 }

  condition:
    any of them
}