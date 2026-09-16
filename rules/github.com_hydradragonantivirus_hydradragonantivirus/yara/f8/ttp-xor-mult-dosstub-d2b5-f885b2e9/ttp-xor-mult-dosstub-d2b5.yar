rule TTP_XOR_MULT_DOSStub_d2b5 {
  strings:
    $key_d2b5 = { 86 dd [2] f2 c5 [2] b5 c7 [2] f2 d6 [2] bc da [2] b0 d0 [2] a7 db [2] bc 95 [2] 81 }

  condition:
    any of them
}