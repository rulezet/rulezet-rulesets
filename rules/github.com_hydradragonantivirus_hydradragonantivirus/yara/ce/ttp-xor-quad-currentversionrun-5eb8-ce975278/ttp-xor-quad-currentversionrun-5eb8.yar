rule TTP_XOR_QUAD_CurrentVersionRun_5eb8 {
  strings:
    $key_5eb8 = { 0d d7 [2] 29 d9 [2] 02 f5 [2] 2c d7 [2] 38 cc [2] 37 d6 [2] 29 cb [2] 2b ca [2] 30 cc [2] 2c cb [2] 30 e4 }

  condition:
    any of them
}