rule TTP_XOR_MULT_DOSStub_d7be {
  strings:
    $key_d7be = { 83 d6 [2] f7 ce [2] b0 cc [2] f7 dd [2] b9 d1 [2] b5 db [2] a2 d0 [2] b9 9e [2] 84 }

  condition:
    any of them
}