rule TTP_XOR_MULT_DOSStub_d2a9 {
  strings:
    $key_d2a9 = { 86 c1 [2] f2 d9 [2] b5 db [2] f2 ca [2] bc c6 [2] b0 cc [2] a7 c7 [2] bc 89 [2] 81 }

  condition:
    any of them
}