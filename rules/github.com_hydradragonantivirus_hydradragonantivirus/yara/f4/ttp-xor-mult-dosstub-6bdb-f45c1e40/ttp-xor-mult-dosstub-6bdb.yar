rule TTP_XOR_MULT_DOSStub_6bdb {
  strings:
    $key_6bdb = { 3f b3 [2] 4b ab [2] 0c a9 [2] 4b b8 [2] 05 b4 [2] 09 be [2] 1e b5 [2] 05 fb [2] 38 }

  condition:
    any of them
}