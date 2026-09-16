rule TTP_XOR_MULT_DOSStub_fb87 {
  strings:
    $key_fb87 = { af ef [2] db f7 [2] 9c f5 [2] db e4 [2] 95 e8 [2] 99 e2 [2] 8e e9 [2] 95 a7 [2] a8 }

  condition:
    any of them
}