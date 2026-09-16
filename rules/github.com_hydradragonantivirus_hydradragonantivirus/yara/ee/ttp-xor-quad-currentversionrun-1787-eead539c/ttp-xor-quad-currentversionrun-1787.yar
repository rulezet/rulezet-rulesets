rule TTP_XOR_QUAD_CurrentVersionRun_1787 {
  strings:
    $key_1787 = { 44 e8 [2] 60 e6 [2] 4b ca [2] 65 e8 [2] 71 f3 [2] 7e e9 [2] 60 f4 [2] 62 f5 [2] 79 f3 [2] 65 f4 [2] 79 db }

  condition:
    any of them
}