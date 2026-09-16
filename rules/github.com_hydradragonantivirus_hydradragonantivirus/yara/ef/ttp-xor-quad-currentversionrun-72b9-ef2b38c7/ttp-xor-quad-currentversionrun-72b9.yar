rule TTP_XOR_QUAD_CurrentVersionRun_72b9 {
  strings:
    $key_72b9 = { 21 d6 [2] 05 d8 [2] 2e f4 [2] 00 d6 [2] 14 cd [2] 1b d7 [2] 05 ca [2] 07 cb [2] 1c cd [2] 00 ca [2] 1c e5 }

  condition:
    any of them
}