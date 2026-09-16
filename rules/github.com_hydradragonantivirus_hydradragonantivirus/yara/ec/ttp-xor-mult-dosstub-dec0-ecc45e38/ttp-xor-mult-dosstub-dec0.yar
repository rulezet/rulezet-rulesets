rule TTP_XOR_MULT_DOSStub_dec0 {
  strings:
    $key_dec0 = { 8a a8 [2] fe b0 [2] b9 b2 [2] fe a3 [2] b0 af [2] bc a5 [2] ab ae [2] b0 e0 [2] 8d }

  condition:
    any of them
}