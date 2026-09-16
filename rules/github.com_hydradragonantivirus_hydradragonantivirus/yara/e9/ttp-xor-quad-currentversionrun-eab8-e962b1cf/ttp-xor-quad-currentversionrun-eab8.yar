rule TTP_XOR_QUAD_CurrentVersionRun_eab8 {
  strings:
    $key_eab8 = { b9 d7 [2] 9d d9 [2] b6 f5 [2] 98 d7 [2] 8c cc [2] 83 d6 [2] 9d cb [2] 9f ca [2] 84 cc [2] 98 cb [2] 84 e4 }

  condition:
    any of them
}