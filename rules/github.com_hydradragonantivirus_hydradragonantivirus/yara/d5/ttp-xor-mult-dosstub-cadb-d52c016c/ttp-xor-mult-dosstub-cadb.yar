rule TTP_XOR_MULT_DOSStub_cadb {
  strings:
    $key_cadb = { 9e b3 [2] ea ab [2] ad a9 [2] ea b8 [2] a4 b4 [2] a8 be [2] bf b5 [2] a4 fb [2] 99 }

  condition:
    any of them
}