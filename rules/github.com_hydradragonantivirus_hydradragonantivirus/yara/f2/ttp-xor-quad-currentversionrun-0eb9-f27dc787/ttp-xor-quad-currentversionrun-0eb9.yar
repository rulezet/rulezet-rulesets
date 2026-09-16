rule TTP_XOR_QUAD_CurrentVersionRun_0eb9 {
  strings:
    $key_0eb9 = { 5d d6 [2] 79 d8 [2] 52 f4 [2] 7c d6 [2] 68 cd [2] 67 d7 [2] 79 ca [2] 7b cb [2] 60 cd [2] 7c ca [2] 60 e5 }

  condition:
    any of them
}