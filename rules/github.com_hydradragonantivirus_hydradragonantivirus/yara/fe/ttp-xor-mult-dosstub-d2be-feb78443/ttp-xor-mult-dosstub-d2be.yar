rule TTP_XOR_MULT_DOSStub_d2be {
  strings:
    $key_d2be = { 86 d6 [2] f2 ce [2] b5 cc [2] f2 dd [2] bc d1 [2] b0 db [2] a7 d0 [2] bc 9e [2] 81 }

  condition:
    any of them
}