rule TTP_XOR_MULT_DOSStub_dbbe {
  strings:
    $key_dbbe = { 8f d6 [2] fb ce [2] bc cc [2] fb dd [2] b5 d1 [2] b9 db [2] ae d0 [2] b5 9e [2] 88 }

  condition:
    any of them
}