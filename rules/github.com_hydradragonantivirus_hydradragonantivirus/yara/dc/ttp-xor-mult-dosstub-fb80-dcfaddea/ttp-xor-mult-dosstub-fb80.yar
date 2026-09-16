rule TTP_XOR_MULT_DOSStub_fb80 {
  strings:
    $key_fb80 = { af e8 [2] db f0 [2] 9c f2 [2] db e3 [2] 95 ef [2] 99 e5 [2] 8e ee [2] 95 a0 [2] a8 }

  condition:
    any of them
}