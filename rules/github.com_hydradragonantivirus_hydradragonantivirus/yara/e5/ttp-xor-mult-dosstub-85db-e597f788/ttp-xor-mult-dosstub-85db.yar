rule TTP_XOR_MULT_DOSStub_85db {
  strings:
    $key_85db = { d1 b3 [2] a5 ab [2] e2 a9 [2] a5 b8 [2] eb b4 [2] e7 be [2] f0 b5 [2] eb fb [2] d6 }

  condition:
    any of them
}