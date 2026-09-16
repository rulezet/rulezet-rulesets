rule TTP_XOR_QUAD_CurrentVersionRun_5587 {
  strings:
    $key_5587 = { 06 e8 [2] 22 e6 [2] 09 ca [2] 27 e8 [2] 33 f3 [2] 3c e9 [2] 22 f4 [2] 20 f5 [2] 3b f3 [2] 27 f4 [2] 3b db }

  condition:
    any of them
}