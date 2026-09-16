rule TTP_XOR_MULT_DOSStub_b7be {
  strings:
    $key_b7be = { e3 d6 [2] 97 ce [2] d0 cc [2] 97 dd [2] d9 d1 [2] d5 db [2] c2 d0 [2] d9 9e [2] e4 }

  condition:
    any of them
}