rule TTP_XOR_MULT_DOSStub_fbd2 {
  strings:
    $key_fbd2 = { af ba [2] db a2 [2] 9c a0 [2] db b1 [2] 95 bd [2] 99 b7 [2] 8e bc [2] 95 f2 [2] a8 }

  condition:
    any of them
}