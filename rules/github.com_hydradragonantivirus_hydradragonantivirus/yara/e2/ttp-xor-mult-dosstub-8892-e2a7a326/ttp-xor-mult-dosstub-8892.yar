rule TTP_XOR_MULT_DOSStub_8892 {
  strings:
    $key_8892 = { dc fa [2] a8 e2 [2] ef e0 [2] a8 f1 [2] e6 fd [2] ea f7 [2] fd fc [2] e6 b2 [2] db }

  condition:
    any of them
}