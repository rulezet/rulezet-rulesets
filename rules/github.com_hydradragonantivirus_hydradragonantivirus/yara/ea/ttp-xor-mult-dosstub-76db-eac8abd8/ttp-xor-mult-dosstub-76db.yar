rule TTP_XOR_MULT_DOSStub_76db {
  strings:
    $key_76db = { 22 b3 [2] 56 ab [2] 11 a9 [2] 56 b8 [2] 18 b4 [2] 14 be [2] 03 b5 [2] 18 fb [2] 25 }

  condition:
    any of them
}