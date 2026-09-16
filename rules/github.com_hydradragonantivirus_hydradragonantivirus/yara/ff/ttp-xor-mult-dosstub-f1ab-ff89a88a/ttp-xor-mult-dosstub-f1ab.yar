rule TTP_XOR_MULT_DOSStub_f1ab {
  strings:
    $key_f1ab = { a5 c3 [2] d1 db [2] 96 d9 [2] d1 c8 [2] 9f c4 [2] 93 ce [2] 84 c5 [2] 9f 8b [2] a2 }

  condition:
    any of them
}