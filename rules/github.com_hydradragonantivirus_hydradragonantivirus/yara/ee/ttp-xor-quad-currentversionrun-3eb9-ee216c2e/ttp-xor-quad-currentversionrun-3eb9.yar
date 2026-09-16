rule TTP_XOR_QUAD_CurrentVersionRun_3eb9 {
  strings:
    $key_3eb9 = { 6d d6 [2] 49 d8 [2] 62 f4 [2] 4c d6 [2] 58 cd [2] 57 d7 [2] 49 ca [2] 4b cb [2] 50 cd [2] 4c ca [2] 50 e5 }

  condition:
    any of them
}