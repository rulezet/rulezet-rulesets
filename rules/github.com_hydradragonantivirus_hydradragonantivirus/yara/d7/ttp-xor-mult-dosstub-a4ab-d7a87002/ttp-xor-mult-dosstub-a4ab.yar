rule TTP_XOR_MULT_DOSStub_a4ab {
  strings:
    $key_a4ab = { f0 c3 [2] 84 db [2] c3 d9 [2] 84 c8 [2] ca c4 [2] c6 ce [2] d1 c5 [2] ca 8b [2] f7 }

  condition:
    any of them
}