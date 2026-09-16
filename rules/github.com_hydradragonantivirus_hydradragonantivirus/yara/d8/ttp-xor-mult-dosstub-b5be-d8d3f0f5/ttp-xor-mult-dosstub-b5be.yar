rule TTP_XOR_MULT_DOSStub_b5be {
  strings:
    $key_b5be = { e1 d6 [2] 95 ce [2] d2 cc [2] 95 dd [2] db d1 [2] d7 db [2] c0 d0 [2] db 9e [2] e6 }

  condition:
    any of them
}