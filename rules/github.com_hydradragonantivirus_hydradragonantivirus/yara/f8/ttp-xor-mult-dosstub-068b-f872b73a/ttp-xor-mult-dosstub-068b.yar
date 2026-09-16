rule TTP_XOR_MULT_DOSStub_068b {
  strings:
    $key_068b = { 52 e3 [2] 26 fb [2] 61 f9 [2] 26 e8 [2] 68 e4 [2] 64 ee [2] 73 e5 [2] 68 ab [2] 55 }

  condition:
    any of them
}