rule TTP_XOR_MULT_DOSStub_c0be {
  strings:
    $key_c0be = { 94 d6 [2] e0 ce [2] a7 cc [2] e0 dd [2] ae d1 [2] a2 db [2] b5 d0 [2] ae 9e [2] 93 }

  condition:
    any of them
}