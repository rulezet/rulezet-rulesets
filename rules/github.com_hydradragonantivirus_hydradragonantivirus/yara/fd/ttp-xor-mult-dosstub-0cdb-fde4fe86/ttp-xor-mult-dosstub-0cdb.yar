rule TTP_XOR_MULT_DOSStub_0cdb {
  strings:
    $key_0cdb = { 58 b3 [2] 2c ab [2] 6b a9 [2] 2c b8 [2] 62 b4 [2] 6e be [2] 79 b5 [2] 62 fb [2] 5f }

  condition:
    any of them
}