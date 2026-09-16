rule TTP_XOR_MULT_DOSStub_d2f8 {
  strings:
    $key_d2f8 = { 86 90 [2] f2 88 [2] b5 8a [2] f2 9b [2] bc 97 [2] b0 9d [2] a7 96 [2] bc d8 [2] 81 }

  condition:
    any of them
}