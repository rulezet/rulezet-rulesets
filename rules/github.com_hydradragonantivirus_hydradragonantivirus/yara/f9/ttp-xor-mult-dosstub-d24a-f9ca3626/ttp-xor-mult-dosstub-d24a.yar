rule TTP_XOR_MULT_DOSStub_d24a {
  strings:
    $key_d24a = { 86 22 [2] f2 3a [2] b5 38 [2] f2 29 [2] bc 25 [2] b0 2f [2] a7 24 [2] bc 6a [2] 81 }

  condition:
    any of them
}