rule TTP_XOR_MULT_DOSStub_d2c0 {
  strings:
    $key_d2c0 = { 86 a8 [2] f2 b0 [2] b5 b2 [2] f2 a3 [2] bc af [2] b0 a5 [2] a7 ae [2] bc e0 [2] 81 }

  condition:
    any of them
}