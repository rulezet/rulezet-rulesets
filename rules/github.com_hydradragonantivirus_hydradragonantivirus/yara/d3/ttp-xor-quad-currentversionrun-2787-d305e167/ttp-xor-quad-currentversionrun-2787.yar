rule TTP_XOR_QUAD_CurrentVersionRun_2787 {
  strings:
    $key_2787 = { 74 e8 [2] 50 e6 [2] 7b ca [2] 55 e8 [2] 41 f3 [2] 4e e9 [2] 50 f4 [2] 52 f5 [2] 49 f3 [2] 55 f4 [2] 49 db }

  condition:
    any of them
}