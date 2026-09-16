rule TTP_XOR_MULT_DOSStub_c396 {
  strings:
    $key_c396 = { 97 fe [2] e3 e6 [2] a4 e4 [2] e3 f5 [2] ad f9 [2] a1 f3 [2] b6 f8 [2] ad b6 [2] 90 }

  condition:
    any of them
}