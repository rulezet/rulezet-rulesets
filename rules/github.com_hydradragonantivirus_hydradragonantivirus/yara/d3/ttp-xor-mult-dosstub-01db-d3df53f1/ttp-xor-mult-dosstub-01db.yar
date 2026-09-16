rule TTP_XOR_MULT_DOSStub_01db {
  strings:
    $key_01db = { 55 b3 [2] 21 ab [2] 66 a9 [2] 21 b8 [2] 6f b4 [2] 63 be [2] 74 b5 [2] 6f fb [2] 52 }

  condition:
    any of them
}