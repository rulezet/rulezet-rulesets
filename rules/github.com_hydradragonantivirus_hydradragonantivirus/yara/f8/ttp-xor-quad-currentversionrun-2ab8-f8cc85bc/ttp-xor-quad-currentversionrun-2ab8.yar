rule TTP_XOR_QUAD_CurrentVersionRun_2ab8 {
  strings:
    $key_2ab8 = { 79 d7 [2] 5d d9 [2] 76 f5 [2] 58 d7 [2] 4c cc [2] 43 d6 [2] 5d cb [2] 5f ca [2] 44 cc [2] 58 cb [2] 44 e4 }

  condition:
    any of them
}