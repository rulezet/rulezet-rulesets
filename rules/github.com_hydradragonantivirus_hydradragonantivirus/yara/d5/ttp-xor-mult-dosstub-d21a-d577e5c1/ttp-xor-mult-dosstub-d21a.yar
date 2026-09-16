rule TTP_XOR_MULT_DOSStub_d21a {
  strings:
    $key_d21a = { 86 72 [2] f2 6a [2] b5 68 [2] f2 79 [2] bc 75 [2] b0 7f [2] a7 74 [2] bc 3a [2] 81 }

  condition:
    any of them
}