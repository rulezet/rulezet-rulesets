rule TTP_XOR_MULT_DOSStub_d0be {
  strings:
    $key_d0be = { 84 d6 [2] f0 ce [2] b7 cc [2] f0 dd [2] be d1 [2] b2 db [2] a5 d0 [2] be 9e [2] 83 }

  condition:
    any of them
}