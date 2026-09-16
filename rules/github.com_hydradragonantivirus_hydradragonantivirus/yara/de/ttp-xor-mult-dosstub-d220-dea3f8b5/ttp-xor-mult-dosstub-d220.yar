rule TTP_XOR_MULT_DOSStub_d220 {
  strings:
    $key_d220 = { 86 48 [2] f2 50 [2] b5 52 [2] f2 43 [2] bc 4f [2] b0 45 [2] a7 4e [2] bc 00 [2] 81 }

  condition:
    any of them
}