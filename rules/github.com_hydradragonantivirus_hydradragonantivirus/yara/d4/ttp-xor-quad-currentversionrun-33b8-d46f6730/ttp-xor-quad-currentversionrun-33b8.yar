rule TTP_XOR_QUAD_CurrentVersionRun_33b8 {
  strings:
    $key_33b8 = { 60 d7 [2] 44 d9 [2] 6f f5 [2] 41 d7 [2] 55 cc [2] 5a d6 [2] 44 cb [2] 46 ca [2] 5d cc [2] 41 cb [2] 5d e4 }

  condition:
    any of them
}