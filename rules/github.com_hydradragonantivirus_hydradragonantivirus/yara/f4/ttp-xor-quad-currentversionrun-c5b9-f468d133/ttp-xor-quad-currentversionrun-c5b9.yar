rule TTP_XOR_QUAD_CurrentVersionRun_c5b9 {
  strings:
    $key_c5b9 = { 96 d6 [2] b2 d8 [2] 99 f4 [2] b7 d6 [2] a3 cd [2] ac d7 [2] b2 ca [2] b0 cb [2] ab cd [2] b7 ca [2] ab e5 }

  condition:
    any of them
}