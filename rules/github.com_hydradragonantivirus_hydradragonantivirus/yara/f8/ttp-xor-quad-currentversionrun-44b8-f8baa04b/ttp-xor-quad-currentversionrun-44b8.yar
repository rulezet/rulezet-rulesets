rule TTP_XOR_QUAD_CurrentVersionRun_44b8 {
  strings:
    $key_44b8 = { 17 d7 [2] 33 d9 [2] 18 f5 [2] 36 d7 [2] 22 cc [2] 2d d6 [2] 33 cb [2] 31 ca [2] 2a cc [2] 36 cb [2] 2a e4 }

  condition:
    any of them
}