rule TTP_XOR_MULT_DOSStub_94ab {
  strings:
    $key_94ab = { c0 c3 [2] b4 db [2] f3 d9 [2] b4 c8 [2] fa c4 [2] f6 ce [2] e1 c5 [2] fa 8b [2] c7 }

  condition:
    any of them
}