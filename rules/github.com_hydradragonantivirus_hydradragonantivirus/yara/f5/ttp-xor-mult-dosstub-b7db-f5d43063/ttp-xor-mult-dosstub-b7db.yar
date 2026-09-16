rule TTP_XOR_MULT_DOSStub_b7db {
  strings:
    $key_b7db = { e3 b3 [2] 97 ab [2] d0 a9 [2] 97 b8 [2] d9 b4 [2] d5 be [2] c2 b5 [2] d9 fb [2] e4 }

  condition:
    any of them
}