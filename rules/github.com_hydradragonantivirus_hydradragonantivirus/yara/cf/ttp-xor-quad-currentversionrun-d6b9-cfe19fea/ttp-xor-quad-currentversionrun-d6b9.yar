rule TTP_XOR_QUAD_CurrentVersionRun_d6b9 {
  strings:
    $key_d6b9 = { 85 d6 [2] a1 d8 [2] 8a f4 [2] a4 d6 [2] b0 cd [2] bf d7 [2] a1 ca [2] a3 cb [2] b8 cd [2] a4 ca [2] b8 e5 }

  condition:
    any of them
}