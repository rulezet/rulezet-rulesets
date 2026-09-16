rule TTP_XOR_MULT_DOSStub_43db {
  strings:
    $key_43db = { 17 b3 [2] 63 ab [2] 24 a9 [2] 63 b8 [2] 2d b4 [2] 21 be [2] 36 b5 [2] 2d fb [2] 10 }

  condition:
    any of them
}