rule TTP_XOR_MULT_DOSStub_d23a {
  strings:
    $key_d23a = { 86 52 [2] f2 4a [2] b5 48 [2] f2 59 [2] bc 55 [2] b0 5f [2] a7 54 [2] bc 1a [2] 81 }

  condition:
    any of them
}