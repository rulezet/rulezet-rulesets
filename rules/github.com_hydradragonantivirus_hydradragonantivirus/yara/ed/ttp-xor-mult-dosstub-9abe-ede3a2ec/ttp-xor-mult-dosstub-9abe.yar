rule TTP_XOR_MULT_DOSStub_9abe {
  strings:
    $key_9abe = { ce d6 [2] ba ce [2] fd cc [2] ba dd [2] f4 d1 [2] f8 db [2] ef d0 [2] f4 9e [2] c9 }

  condition:
    any of them
}