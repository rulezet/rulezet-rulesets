rule TTP_XOR_MULT_DOSStub_d23f {
  strings:
    $key_d23f = { 86 57 [2] f2 4f [2] b5 4d [2] f2 5c [2] bc 50 [2] b0 5a [2] a7 51 [2] bc 1f [2] 81 }

  condition:
    any of them
}