rule TTP_XOR_MULT_DOSStub_a4be {
  strings:
    $key_a4be = { f0 d6 [2] 84 ce [2] c3 cc [2] 84 dd [2] ca d1 [2] c6 db [2] d1 d0 [2] ca 9e [2] f7 }

  condition:
    any of them
}