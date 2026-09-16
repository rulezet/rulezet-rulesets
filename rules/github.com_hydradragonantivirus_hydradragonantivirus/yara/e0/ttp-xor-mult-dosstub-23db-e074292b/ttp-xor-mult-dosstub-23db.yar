rule TTP_XOR_MULT_DOSStub_23db {
  strings:
    $key_23db = { 77 b3 [2] 03 ab [2] 44 a9 [2] 03 b8 [2] 4d b4 [2] 41 be [2] 56 b5 [2] 4d fb [2] 70 }

  condition:
    any of them
}