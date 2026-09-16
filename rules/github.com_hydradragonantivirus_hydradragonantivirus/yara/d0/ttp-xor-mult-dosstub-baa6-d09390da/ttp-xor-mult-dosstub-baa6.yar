rule TTP_XOR_MULT_DOSStub_baa6 {
  strings:
    $key_baa6 = { ee ce [2] 9a d6 [2] dd d4 [2] 9a c5 [2] d4 c9 [2] d8 c3 [2] cf c8 [2] d4 86 [2] e9 }

  condition:
    any of them
}