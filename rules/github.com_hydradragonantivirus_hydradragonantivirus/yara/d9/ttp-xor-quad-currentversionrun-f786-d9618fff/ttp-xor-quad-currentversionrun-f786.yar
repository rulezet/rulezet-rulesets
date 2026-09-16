rule TTP_XOR_QUAD_CurrentVersionRun_f786 {
  strings:
    $key_f786 = { a4 e9 [2] 80 e7 [2] ab cb [2] 85 e9 [2] 91 f2 [2] 9e e8 [2] 80 f5 [2] 82 f4 [2] 99 f2 [2] 85 f5 [2] 99 da }

  condition:
    any of them
}