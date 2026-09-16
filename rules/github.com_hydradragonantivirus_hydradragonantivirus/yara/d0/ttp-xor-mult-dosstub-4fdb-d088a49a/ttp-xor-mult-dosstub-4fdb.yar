rule TTP_XOR_MULT_DOSStub_4fdb {
  strings:
    $key_4fdb = { 1b b3 [2] 6f ab [2] 28 a9 [2] 6f b8 [2] 21 b4 [2] 2d be [2] 3a b5 [2] 21 fb [2] 1c }

  condition:
    any of them
}