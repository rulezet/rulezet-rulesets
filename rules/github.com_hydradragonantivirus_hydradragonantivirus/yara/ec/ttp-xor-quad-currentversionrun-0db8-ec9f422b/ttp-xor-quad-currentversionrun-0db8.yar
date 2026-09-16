rule TTP_XOR_QUAD_CurrentVersionRun_0db8 {
  strings:
    $key_0db8 = { 5e d7 [2] 7a d9 [2] 51 f5 [2] 7f d7 [2] 6b cc [2] 64 d6 [2] 7a cb [2] 78 ca [2] 63 cc [2] 7f cb [2] 63 e4 }

  condition:
    any of them
}