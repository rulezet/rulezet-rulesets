rule TTP_XOR_MULT_DOSStub_cc8b {
  strings:
    $key_cc8b = { 98 e3 [2] ec fb [2] ab f9 [2] ec e8 [2] a2 e4 [2] ae ee [2] b9 e5 [2] a2 ab [2] 9f }

  condition:
    any of them
}