rule TTP_XOR_QUAD_CurrentVersionRun_f3b9 {
  strings:
    $key_f3b9 = { a0 d6 [2] 84 d8 [2] af f4 [2] 81 d6 [2] 95 cd [2] 9a d7 [2] 84 ca [2] 86 cb [2] 9d cd [2] 81 ca [2] 9d e5 }

  condition:
    any of them
}