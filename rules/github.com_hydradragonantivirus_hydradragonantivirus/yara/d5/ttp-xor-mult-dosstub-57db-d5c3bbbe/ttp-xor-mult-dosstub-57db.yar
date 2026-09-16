rule TTP_XOR_MULT_DOSStub_57db {
  strings:
    $key_57db = { 03 b3 [2] 77 ab [2] 30 a9 [2] 77 b8 [2] 39 b4 [2] 35 be [2] 22 b5 [2] 39 fb [2] 04 }

  condition:
    any of them
}