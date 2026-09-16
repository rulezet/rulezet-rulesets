rule TTP_XOR_MULT_DOSStub_97db {
  strings:
    $key_97db = { c3 b3 [2] b7 ab [2] f0 a9 [2] b7 b8 [2] f9 b4 [2] f5 be [2] e2 b5 [2] f9 fb [2] c4 }

  condition:
    any of them
}