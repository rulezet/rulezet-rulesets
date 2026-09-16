rule TTP_XOR_QUAD_CurrentVersionRun_d0b8 {
  strings:
    $key_d0b8 = { 83 d7 [2] a7 d9 [2] 8c f5 [2] a2 d7 [2] b6 cc [2] b9 d6 [2] a7 cb [2] a5 ca [2] be cc [2] a2 cb [2] be e4 }

  condition:
    any of them
}