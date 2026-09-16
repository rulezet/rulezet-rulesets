rule TTP_XOR_MULT_DOSStub_fb96 {
  strings:
    $key_fb96 = { af fe [2] db e6 [2] 9c e4 [2] db f5 [2] 95 f9 [2] 99 f3 [2] 8e f8 [2] 95 b6 [2] a8 }

  condition:
    any of them
}