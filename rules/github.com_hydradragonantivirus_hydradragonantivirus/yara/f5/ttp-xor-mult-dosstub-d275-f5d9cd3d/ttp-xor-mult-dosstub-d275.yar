rule TTP_XOR_MULT_DOSStub_d275 {
  strings:
    $key_d275 = { 86 1d [2] f2 05 [2] b5 07 [2] f2 16 [2] bc 1a [2] b0 10 [2] a7 1b [2] bc 55 [2] 81 }

  condition:
    any of them
}