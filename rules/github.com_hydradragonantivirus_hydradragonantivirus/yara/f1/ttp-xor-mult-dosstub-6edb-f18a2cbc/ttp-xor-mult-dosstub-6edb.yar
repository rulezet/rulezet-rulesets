rule TTP_XOR_MULT_DOSStub_6edb {
  strings:
    $key_6edb = { 3a b3 [2] 4e ab [2] 09 a9 [2] 4e b8 [2] 00 b4 [2] 0c be [2] 1b b5 [2] 00 fb [2] 3d }

  condition:
    any of them
}