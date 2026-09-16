rule TTP_XOR_QUAD_CurrentVersionRun_15a4 {
  strings:
    $key_15a4 = { 46 cb [2] 62 c5 [2] 49 e9 [2] 67 cb [2] 73 d0 [2] 7c ca [2] 62 d7 [2] 60 d6 [2] 7b d0 [2] 67 d7 [2] 7b f8 }

  condition:
    any of them
}