rule TTP_XOR_MULT_DOSStub_539e {
  strings:
    $key_539e = { 07 f6 [2] 73 ee [2] 34 ec [2] 73 fd [2] 3d f1 [2] 31 fb [2] 26 f0 [2] 3d be [2] 00 }

  condition:
    any of them
}