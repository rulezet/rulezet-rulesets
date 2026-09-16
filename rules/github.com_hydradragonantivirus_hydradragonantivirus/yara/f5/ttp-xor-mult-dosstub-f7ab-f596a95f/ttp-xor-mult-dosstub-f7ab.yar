rule TTP_XOR_MULT_DOSStub_f7ab {
  strings:
    $key_f7ab = { a3 c3 [2] d7 db [2] 90 d9 [2] d7 c8 [2] 99 c4 [2] 95 ce [2] 82 c5 [2] 99 8b [2] a4 }

  condition:
    any of them
}