rule TTP_XOR_MULT_DOSStub_e7db {
  strings:
    $key_e7db = { b3 b3 [2] c7 ab [2] 80 a9 [2] c7 b8 [2] 89 b4 [2] 85 be [2] 92 b5 [2] 89 fb [2] b4 }

  condition:
    any of them
}