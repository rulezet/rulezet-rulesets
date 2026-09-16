rule TTP_XOR_MULT_DOSStub_8b92 {
  strings:
    $key_8b92 = { df fa [2] ab e2 [2] ec e0 [2] ab f1 [2] e5 fd [2] e9 f7 [2] fe fc [2] e5 b2 [2] d8 }

  condition:
    any of them
}