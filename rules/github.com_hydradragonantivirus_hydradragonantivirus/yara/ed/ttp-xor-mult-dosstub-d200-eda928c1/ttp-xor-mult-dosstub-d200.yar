rule TTP_XOR_MULT_DOSStub_d200 {
  strings:
    $key_d200 = { 86 68 [2] f2 70 [2] b5 72 [2] f2 63 [2] bc 6f [2] b0 65 [2] a7 6e [2] bc 20 [2] 81 }

  condition:
    any of them
}