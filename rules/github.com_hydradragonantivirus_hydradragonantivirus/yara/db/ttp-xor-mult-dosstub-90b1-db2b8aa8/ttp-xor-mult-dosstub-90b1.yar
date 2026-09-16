rule TTP_XOR_MULT_DOSStub_90b1 {
  strings:
    $key_90b1 = { c4 d9 [2] b0 c1 [2] f7 c3 [2] b0 d2 [2] fe de [2] f2 d4 [2] e5 df [2] fe 91 [2] c3 }

  condition:
    any of them
}