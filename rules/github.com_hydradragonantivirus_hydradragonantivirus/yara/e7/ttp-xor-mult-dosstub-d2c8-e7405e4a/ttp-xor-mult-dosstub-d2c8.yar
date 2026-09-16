rule TTP_XOR_MULT_DOSStub_d2c8 {
  strings:
    $key_d2c8 = { 86 a0 [2] f2 b8 [2] b5 ba [2] f2 ab [2] bc a7 [2] b0 ad [2] a7 a6 [2] bc e8 [2] 81 }

  condition:
    any of them
}