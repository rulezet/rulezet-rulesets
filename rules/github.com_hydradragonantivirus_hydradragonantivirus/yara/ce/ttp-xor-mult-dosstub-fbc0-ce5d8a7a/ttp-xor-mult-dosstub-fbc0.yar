rule TTP_XOR_MULT_DOSStub_fbc0 {
  strings:
    $key_fbc0 = { af a8 [2] db b0 [2] 9c b2 [2] db a3 [2] 95 af [2] 99 a5 [2] 8e ae [2] 95 e0 [2] a8 }

  condition:
    any of them
}