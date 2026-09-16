rule TTP_XOR_MULT_DOSStub_f0be {
  strings:
    $key_f0be = { a4 d6 [2] d0 ce [2] 97 cc [2] d0 dd [2] 9e d1 [2] 92 db [2] 85 d0 [2] 9e 9e [2] a3 }

  condition:
    any of them
}