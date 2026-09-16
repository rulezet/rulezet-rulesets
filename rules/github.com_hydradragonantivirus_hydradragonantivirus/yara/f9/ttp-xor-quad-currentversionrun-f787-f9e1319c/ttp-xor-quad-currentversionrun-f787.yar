rule TTP_XOR_QUAD_CurrentVersionRun_f787 {
  strings:
    $key_f787 = { a4 e8 [2] 80 e6 [2] ab ca [2] 85 e8 [2] 91 f3 [2] 9e e9 [2] 80 f4 [2] 82 f5 [2] 99 f3 [2] 85 f4 [2] 99 db }

  condition:
    any of them
}