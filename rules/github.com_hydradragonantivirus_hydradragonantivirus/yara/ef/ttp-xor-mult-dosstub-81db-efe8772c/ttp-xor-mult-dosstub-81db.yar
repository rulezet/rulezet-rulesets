rule TTP_XOR_MULT_DOSStub_81db {
  strings:
    $key_81db = { d5 b3 [2] a1 ab [2] e6 a9 [2] a1 b8 [2] ef b4 [2] e3 be [2] f4 b5 [2] ef fb [2] d2 }

  condition:
    any of them
}