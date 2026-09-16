rule TTP_XOR_MULT_DOSStub_b0db {
  strings:
    $key_b0db = { e4 b3 [2] 90 ab [2] d7 a9 [2] 90 b8 [2] de b4 [2] d2 be [2] c5 b5 [2] de fb [2] e3 }

  condition:
    any of them
}