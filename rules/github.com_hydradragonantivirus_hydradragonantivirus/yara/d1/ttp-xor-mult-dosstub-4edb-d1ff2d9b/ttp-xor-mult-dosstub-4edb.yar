rule TTP_XOR_MULT_DOSStub_4edb {
  strings:
    $key_4edb = { 1a b3 [2] 6e ab [2] 29 a9 [2] 6e b8 [2] 20 b4 [2] 2c be [2] 3b b5 [2] 20 fb [2] 1d }

  condition:
    any of them
}