rule TTP_XOR_MULT_DOSStub_d2b3 {
  strings:
    $key_d2b3 = { 86 db [2] f2 c3 [2] b5 c1 [2] f2 d0 [2] bc dc [2] b0 d6 [2] a7 dd [2] bc 93 [2] 81 }

  condition:
    any of them
}