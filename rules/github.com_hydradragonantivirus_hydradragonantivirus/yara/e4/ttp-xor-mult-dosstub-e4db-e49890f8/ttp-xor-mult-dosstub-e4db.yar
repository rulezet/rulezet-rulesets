rule TTP_XOR_MULT_DOSStub_e4db {
  strings:
    $key_e4db = { b0 b3 [2] c4 ab [2] 83 a9 [2] c4 b8 [2] 8a b4 [2] 86 be [2] 91 b5 [2] 8a fb [2] b7 }

  condition:
    any of them
}