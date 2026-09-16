rule TTP_XOR_QUAD_CurrentVersionRun_ffa4 {
  strings:
    $key_ffa4 = { ac cb [2] 88 c5 [2] a3 e9 [2] 8d cb [2] 99 d0 [2] 96 ca [2] 88 d7 [2] 8a d6 [2] 91 d0 [2] 8d d7 [2] 91 f8 }

  condition:
    any of them
}