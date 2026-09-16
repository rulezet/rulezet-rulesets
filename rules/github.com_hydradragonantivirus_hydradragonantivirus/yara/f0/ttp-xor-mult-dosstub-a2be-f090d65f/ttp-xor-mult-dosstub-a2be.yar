rule TTP_XOR_MULT_DOSStub_a2be {
  strings:
    $key_a2be = { f6 d6 [2] 82 ce [2] c5 cc [2] 82 dd [2] cc d1 [2] c0 db [2] d7 d0 [2] cc 9e [2] f1 }

  condition:
    any of them
}