rule TTP_XOR_MULT_DOSStub_e693 {
  strings:
    $key_e693 = { b2 fb [2] c6 e3 [2] 81 e1 [2] c6 f0 [2] 88 fc [2] 84 f6 [2] 93 fd [2] 88 b3 [2] b5 }

  condition:
    any of them
}