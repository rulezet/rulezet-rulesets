rule TTP_XOR_QUAD_CurrentVersionRun_c4b8 {
  strings:
    $key_c4b8 = { 97 d7 [2] b3 d9 [2] 98 f5 [2] b6 d7 [2] a2 cc [2] ad d6 [2] b3 cb [2] b1 ca [2] aa cc [2] b6 cb [2] aa e4 }

  condition:
    any of them
}