rule TTP_XOR_MULT_DOSStub_baab {
  strings:
    $key_baab = { ee c3 [2] 9a db [2] dd d9 [2] 9a c8 [2] d4 c4 [2] d8 ce [2] cf c5 [2] d4 8b [2] e9 }

  condition:
    any of them
}