rule TTP_XOR_MULT_DOSStub_d26e {
  strings:
    $key_d26e = { 86 06 [2] f2 1e [2] b5 1c [2] f2 0d [2] bc 01 [2] b0 0b [2] a7 00 [2] bc 4e [2] 81 }

  condition:
    any of them
}