rule TTP_XOR_MULT_DOSStub_e1db {
  strings:
    $key_e1db = { b5 b3 [2] c1 ab [2] 86 a9 [2] c1 b8 [2] 8f b4 [2] 83 be [2] 94 b5 [2] 8f fb [2] b2 }

  condition:
    any of them
}