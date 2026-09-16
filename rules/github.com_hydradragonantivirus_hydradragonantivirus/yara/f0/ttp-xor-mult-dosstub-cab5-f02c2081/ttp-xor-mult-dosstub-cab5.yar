rule TTP_XOR_MULT_DOSStub_cab5 {
  strings:
    $key_cab5 = { 9e dd [2] ea c5 [2] ad c7 [2] ea d6 [2] a4 da [2] a8 d0 [2] bf db [2] a4 95 [2] 99 }

  condition:
    any of them
}