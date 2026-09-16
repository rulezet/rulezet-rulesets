rule TTP_XOR_QUAD_CurrentVersionRun_11b8 {
  strings:
    $key_11b8 = { 42 d7 [2] 66 d9 [2] 4d f5 [2] 63 d7 [2] 77 cc [2] 78 d6 [2] 66 cb [2] 64 ca [2] 7f cc [2] 63 cb [2] 7f e4 }

  condition:
    any of them
}