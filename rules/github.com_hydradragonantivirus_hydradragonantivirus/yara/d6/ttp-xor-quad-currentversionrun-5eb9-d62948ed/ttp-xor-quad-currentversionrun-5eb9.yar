rule TTP_XOR_QUAD_CurrentVersionRun_5eb9 {
  strings:
    $key_5eb9 = { 0d d6 [2] 29 d8 [2] 02 f4 [2] 2c d6 [2] 38 cd [2] 37 d7 [2] 29 ca [2] 2b cb [2] 30 cd [2] 2c ca [2] 30 e5 }

  condition:
    any of them
}