rule TTP_XOR_MULT_DOSStub_dcc0 {
  strings:
    $key_dcc0 = { 88 a8 [2] fc b0 [2] bb b2 [2] fc a3 [2] b2 af [2] be a5 [2] a9 ae [2] b2 e0 [2] 8f }

  condition:
    any of them
}