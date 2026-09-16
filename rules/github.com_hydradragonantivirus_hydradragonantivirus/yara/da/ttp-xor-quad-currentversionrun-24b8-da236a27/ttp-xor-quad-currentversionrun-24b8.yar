rule TTP_XOR_QUAD_CurrentVersionRun_24b8 {
  strings:
    $key_24b8 = { 77 d7 [2] 53 d9 [2] 78 f5 [2] 56 d7 [2] 42 cc [2] 4d d6 [2] 53 cb [2] 51 ca [2] 4a cc [2] 56 cb [2] 4a e4 }

  condition:
    any of them
}