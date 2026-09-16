rule TTP_XOR_MULT_DOSStub_0edb {
  strings:
    $key_0edb = { 5a b3 [2] 2e ab [2] 69 a9 [2] 2e b8 [2] 60 b4 [2] 6c be [2] 7b b5 [2] 60 fb [2] 5d }

  condition:
    any of them
}