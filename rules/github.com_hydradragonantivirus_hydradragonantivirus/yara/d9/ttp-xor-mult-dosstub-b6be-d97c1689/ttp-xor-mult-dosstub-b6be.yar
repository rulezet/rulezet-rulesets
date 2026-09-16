rule TTP_XOR_MULT_DOSStub_b6be {
  strings:
    $key_b6be = { e2 d6 [2] 96 ce [2] d1 cc [2] 96 dd [2] d8 d1 [2] d4 db [2] c3 d0 [2] d8 9e [2] e5 }

  condition:
    any of them
}