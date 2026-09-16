rule TTP_XOR_MULT_DOSStub_d2f0 {
  strings:
    $key_d2f0 = { 86 98 [2] f2 80 [2] b5 82 [2] f2 93 [2] bc 9f [2] b0 95 [2] a7 9e [2] bc d0 [2] 81 }

  condition:
    any of them
}