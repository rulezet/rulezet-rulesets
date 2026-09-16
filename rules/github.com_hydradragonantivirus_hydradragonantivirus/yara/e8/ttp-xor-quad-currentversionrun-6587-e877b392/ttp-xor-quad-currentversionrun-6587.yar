rule TTP_XOR_QUAD_CurrentVersionRun_6587 {
  strings:
    $key_6587 = { 36 e8 [2] 12 e6 [2] 39 ca [2] 17 e8 [2] 03 f3 [2] 0c e9 [2] 12 f4 [2] 10 f5 [2] 0b f3 [2] 17 f4 [2] 0b db }

  condition:
    any of them
}