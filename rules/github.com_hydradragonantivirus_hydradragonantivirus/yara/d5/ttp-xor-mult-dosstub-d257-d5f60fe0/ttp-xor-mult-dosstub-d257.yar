rule TTP_XOR_MULT_DOSStub_d257 {
  strings:
    $key_d257 = { 86 3f [2] f2 27 [2] b5 25 [2] f2 34 [2] bc 38 [2] b0 32 [2] a7 39 [2] bc 77 [2] 81 }

  condition:
    any of them
}