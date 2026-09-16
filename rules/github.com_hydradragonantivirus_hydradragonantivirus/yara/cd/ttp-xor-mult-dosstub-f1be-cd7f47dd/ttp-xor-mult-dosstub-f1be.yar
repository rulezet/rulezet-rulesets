rule TTP_XOR_MULT_DOSStub_f1be {
  strings:
    $key_f1be = { a5 d6 [2] d1 ce [2] 96 cc [2] d1 dd [2] 9f d1 [2] 93 db [2] 84 d0 [2] 9f 9e [2] a2 }

  condition:
    any of them
}