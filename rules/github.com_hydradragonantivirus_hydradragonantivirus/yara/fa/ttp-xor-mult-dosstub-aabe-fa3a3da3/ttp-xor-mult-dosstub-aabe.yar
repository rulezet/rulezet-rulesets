rule TTP_XOR_MULT_DOSStub_aabe {
  strings:
    $key_aabe = { fe d6 [2] 8a ce [2] cd cc [2] 8a dd [2] c4 d1 [2] c8 db [2] df d0 [2] c4 9e [2] f9 }

  condition:
    any of them
}