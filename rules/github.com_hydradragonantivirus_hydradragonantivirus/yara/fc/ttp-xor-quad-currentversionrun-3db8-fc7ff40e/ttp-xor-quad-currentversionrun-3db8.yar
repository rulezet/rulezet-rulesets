rule TTP_XOR_QUAD_CurrentVersionRun_3db8 {
  strings:
    $key_3db8 = { 6e d7 [2] 4a d9 [2] 61 f5 [2] 4f d7 [2] 5b cc [2] 54 d6 [2] 4a cb [2] 48 ca [2] 53 cc [2] 4f cb [2] 53 e4 }

  condition:
    any of them
}