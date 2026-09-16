rule TTP_XOR_MULT_DOSStub_f4be {
  strings:
    $key_f4be = { a0 d6 [2] d4 ce [2] 93 cc [2] d4 dd [2] 9a d1 [2] 96 db [2] 81 d0 [2] 9a 9e [2] a7 }

  condition:
    any of them
}