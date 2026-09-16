rule TTP_XOR_MULT_DOSStub_d23d {
  strings:
    $key_d23d = { 86 55 [2] f2 4d [2] b5 4f [2] f2 5e [2] bc 52 [2] b0 58 [2] a7 53 [2] bc 1d [2] 81 }

  condition:
    any of them
}