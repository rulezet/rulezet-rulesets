rule TTP_XOR_MULT_DOSStub_21be {
  strings:
    $key_21be = { 75 d6 [2] 01 ce [2] 46 cc [2] 01 dd [2] 4f d1 [2] 43 db [2] 54 d0 [2] 4f 9e [2] 72 }

  condition:
    any of them
}