rule TTP_XOR_MULT_DOSStub_90be {
  strings:
    $key_90be = { c4 d6 [2] b0 ce [2] f7 cc [2] b0 dd [2] fe d1 [2] f2 db [2] e5 d0 [2] fe 9e [2] c3 }

  condition:
    any of them
}