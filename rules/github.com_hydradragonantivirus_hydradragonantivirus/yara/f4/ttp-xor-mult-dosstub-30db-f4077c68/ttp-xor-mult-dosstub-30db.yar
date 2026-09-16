rule TTP_XOR_MULT_DOSStub_30db {
  strings:
    $key_30db = { 64 b3 [2] 10 ab [2] 57 a9 [2] 10 b8 [2] 5e b4 [2] 52 be [2] 45 b5 [2] 5e fb [2] 63 }

  condition:
    any of them
}