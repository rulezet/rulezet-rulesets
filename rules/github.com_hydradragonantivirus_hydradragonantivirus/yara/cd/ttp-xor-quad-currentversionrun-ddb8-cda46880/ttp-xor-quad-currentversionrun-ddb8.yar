rule TTP_XOR_QUAD_CurrentVersionRun_ddb8 {
  strings:
    $key_ddb8 = { 8e d7 [2] aa d9 [2] 81 f5 [2] af d7 [2] bb cc [2] b4 d6 [2] aa cb [2] a8 ca [2] b3 cc [2] af cb [2] b3 e4 }

  condition:
    any of them
}