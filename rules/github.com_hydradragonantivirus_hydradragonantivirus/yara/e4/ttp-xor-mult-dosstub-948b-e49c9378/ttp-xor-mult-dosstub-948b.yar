rule TTP_XOR_MULT_DOSStub_948b {
  strings:
    $key_948b = { c0 e3 [2] b4 fb [2] f3 f9 [2] b4 e8 [2] fa e4 [2] f6 ee [2] e1 e5 [2] fa ab [2] c7 }

  condition:
    any of them
}