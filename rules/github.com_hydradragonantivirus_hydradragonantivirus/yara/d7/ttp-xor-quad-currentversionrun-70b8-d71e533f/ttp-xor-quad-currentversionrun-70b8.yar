rule TTP_XOR_QUAD_CurrentVersionRun_70b8 {
  strings:
    $key_70b8 = { 23 d7 [2] 07 d9 [2] 2c f5 [2] 02 d7 [2] 16 cc [2] 19 d6 [2] 07 cb [2] 05 ca [2] 1e cc [2] 02 cb [2] 1e e4 }

  condition:
    any of them
}