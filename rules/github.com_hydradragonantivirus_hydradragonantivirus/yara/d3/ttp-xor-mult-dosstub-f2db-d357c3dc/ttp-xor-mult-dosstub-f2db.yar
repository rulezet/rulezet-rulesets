rule TTP_XOR_MULT_DOSStub_f2db {
  strings:
    $key_f2db = { a6 b3 [2] d2 ab [2] 95 a9 [2] d2 b8 [2] 9c b4 [2] 90 be [2] 87 b5 [2] 9c fb [2] a1 }

  condition:
    any of them
}