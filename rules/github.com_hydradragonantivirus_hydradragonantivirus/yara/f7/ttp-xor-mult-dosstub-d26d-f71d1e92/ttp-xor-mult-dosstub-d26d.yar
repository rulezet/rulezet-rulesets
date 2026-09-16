rule TTP_XOR_MULT_DOSStub_d26d {
  strings:
    $key_d26d = { 86 05 [2] f2 1d [2] b5 1f [2] f2 0e [2] bc 02 [2] b0 08 [2] a7 03 [2] bc 4d [2] 81 }

  condition:
    any of them
}