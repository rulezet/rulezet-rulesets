rule TTP_XOR_QUAD_CurrentVersionRun_1fb9 {
  strings:
    $key_1fb9 = { 4c d6 [2] 68 d8 [2] 43 f4 [2] 6d d6 [2] 79 cd [2] 76 d7 [2] 68 ca [2] 6a cb [2] 71 cd [2] 6d ca [2] 71 e5 }

  condition:
    any of them
}