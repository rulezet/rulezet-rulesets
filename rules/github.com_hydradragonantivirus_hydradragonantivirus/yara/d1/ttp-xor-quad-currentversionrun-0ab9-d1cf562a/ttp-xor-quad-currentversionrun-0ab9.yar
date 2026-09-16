rule TTP_XOR_QUAD_CurrentVersionRun_0ab9 {
  strings:
    $key_0ab9 = { 59 d6 [2] 7d d8 [2] 56 f4 [2] 78 d6 [2] 6c cd [2] 63 d7 [2] 7d ca [2] 7f cb [2] 64 cd [2] 78 ca [2] 64 e5 }

  condition:
    any of them
}