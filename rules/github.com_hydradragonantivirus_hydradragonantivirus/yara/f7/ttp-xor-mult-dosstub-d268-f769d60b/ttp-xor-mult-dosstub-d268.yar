rule TTP_XOR_MULT_DOSStub_d268 {
  strings:
    $key_d268 = { 86 00 [2] f2 18 [2] b5 1a [2] f2 0b [2] bc 07 [2] b0 0d [2] a7 06 [2] bc 48 [2] 81 }

  condition:
    any of them
}