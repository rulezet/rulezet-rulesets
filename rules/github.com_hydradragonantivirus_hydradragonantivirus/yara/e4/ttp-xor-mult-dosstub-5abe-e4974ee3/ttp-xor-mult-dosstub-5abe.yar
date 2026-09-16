rule TTP_XOR_MULT_DOSStub_5abe {
  strings:
    $key_5abe = { 0e d6 [2] 7a ce [2] 3d cc [2] 7a dd [2] 34 d1 [2] 38 db [2] 2f d0 [2] 34 9e [2] 09 }

  condition:
    any of them
}