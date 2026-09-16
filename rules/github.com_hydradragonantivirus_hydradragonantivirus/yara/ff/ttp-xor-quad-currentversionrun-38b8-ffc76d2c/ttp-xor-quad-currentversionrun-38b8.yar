rule TTP_XOR_QUAD_CurrentVersionRun_38b8 {
  strings:
    $key_38b8 = { 6b d7 [2] 4f d9 [2] 64 f5 [2] 4a d7 [2] 5e cc [2] 51 d6 [2] 4f cb [2] 4d ca [2] 56 cc [2] 4a cb [2] 56 e4 }

  condition:
    any of them
}