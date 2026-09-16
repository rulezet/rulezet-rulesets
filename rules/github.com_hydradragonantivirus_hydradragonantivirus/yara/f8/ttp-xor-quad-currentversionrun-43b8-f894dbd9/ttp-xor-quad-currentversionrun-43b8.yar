rule TTP_XOR_QUAD_CurrentVersionRun_43b8 {
  strings:
    $key_43b8 = { 10 d7 [2] 34 d9 [2] 1f f5 [2] 31 d7 [2] 25 cc [2] 2a d6 [2] 34 cb [2] 36 ca [2] 2d cc [2] 31 cb [2] 2d e4 }

  condition:
    any of them
}