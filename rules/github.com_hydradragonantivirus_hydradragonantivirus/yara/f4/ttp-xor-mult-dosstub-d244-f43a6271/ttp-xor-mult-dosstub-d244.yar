rule TTP_XOR_MULT_DOSStub_d244 {
  strings:
    $key_d244 = { 86 2c [2] f2 34 [2] b5 36 [2] f2 27 [2] bc 2b [2] b0 21 [2] a7 2a [2] bc 64 [2] 81 }

  condition:
    any of them
}