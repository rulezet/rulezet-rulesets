rule TTP_XOR_QUAD_CurrentVersionRun_1ab8 {
  strings:
    $key_1ab8 = { 49 d7 [2] 6d d9 [2] 46 f5 [2] 68 d7 [2] 7c cc [2] 73 d6 [2] 6d cb [2] 6f ca [2] 74 cc [2] 68 cb [2] 74 e4 }

  condition:
    any of them
}