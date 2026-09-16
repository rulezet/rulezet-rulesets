rule TTP_XOR_MULT_DOSStub_8991 {
  strings:
    $key_8991 = { dd f9 [2] a9 e1 [2] ee e3 [2] a9 f2 [2] e7 fe [2] eb f4 [2] fc ff [2] e7 b1 [2] da }

  condition:
    any of them
}