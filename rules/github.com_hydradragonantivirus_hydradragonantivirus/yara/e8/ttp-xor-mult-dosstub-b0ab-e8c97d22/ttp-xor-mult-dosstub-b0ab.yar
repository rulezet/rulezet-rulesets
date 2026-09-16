rule TTP_XOR_MULT_DOSStub_b0ab {
  strings:
    $key_b0ab = { e4 c3 [2] 90 db [2] d7 d9 [2] 90 c8 [2] de c4 [2] d2 ce [2] c5 c5 [2] de 8b [2] e3 }

  condition:
    any of them
}