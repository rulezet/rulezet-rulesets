rule TTP_XOR_QUAD_CurrentVersionRun_3787 {
  strings:
    $key_3787 = { 64 e8 [2] 40 e6 [2] 6b ca [2] 45 e8 [2] 51 f3 [2] 5e e9 [2] 40 f4 [2] 42 f5 [2] 59 f3 [2] 45 f4 [2] 59 db }

  condition:
    any of them
}