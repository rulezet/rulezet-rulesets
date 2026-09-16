rule TTP_XOR_MULT_DOSStub_e1be {
  strings:
    $key_e1be = { b5 d6 [2] c1 ce [2] 86 cc [2] c1 dd [2] 8f d1 [2] 83 db [2] 94 d0 [2] 8f 9e [2] b2 }

  condition:
    any of them
}