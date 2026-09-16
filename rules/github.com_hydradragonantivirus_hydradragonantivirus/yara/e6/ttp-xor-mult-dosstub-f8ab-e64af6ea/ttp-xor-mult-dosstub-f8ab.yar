rule TTP_XOR_MULT_DOSStub_f8ab {
  strings:
    $key_f8ab = { ac c3 [2] d8 db [2] 9f d9 [2] d8 c8 [2] 96 c4 [2] 9a ce [2] 8d c5 [2] 96 8b [2] ab }

  condition:
    any of them
}