rule TTP_XOR_MULT_DOSStub_039e {
  strings:
    $key_039e = { 57 f6 [2] 23 ee [2] 64 ec [2] 23 fd [2] 6d f1 [2] 61 fb [2] 76 f0 [2] 6d be [2] 50 }

  condition:
    any of them
}