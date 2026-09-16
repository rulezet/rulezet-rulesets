rule TTP_XOR_MULT_DOSStub_64db {
  strings:
    $key_64db = { 30 b3 [2] 44 ab [2] 03 a9 [2] 44 b8 [2] 0a b4 [2] 06 be [2] 11 b5 [2] 0a fb [2] 37 }

  condition:
    any of them
}