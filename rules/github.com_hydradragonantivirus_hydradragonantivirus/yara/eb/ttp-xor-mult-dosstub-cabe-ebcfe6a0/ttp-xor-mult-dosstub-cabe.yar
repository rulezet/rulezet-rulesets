rule TTP_XOR_MULT_DOSStub_cabe {
  strings:
    $key_cabe = { 9e d6 [2] ea ce [2] ad cc [2] ea dd [2] a4 d1 [2] a8 db [2] bf d0 [2] a4 9e [2] 99 }

  condition:
    any of them
}