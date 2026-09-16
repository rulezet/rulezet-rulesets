rule TTP_XOR_QUAD_CurrentVersionRun_2387 {
  strings:
    $key_2387 = { 70 e8 [2] 54 e6 [2] 7f ca [2] 51 e8 [2] 45 f3 [2] 4a e9 [2] 54 f4 [2] 56 f5 [2] 4d f3 [2] 51 f4 [2] 4d db }

  condition:
    any of them
}