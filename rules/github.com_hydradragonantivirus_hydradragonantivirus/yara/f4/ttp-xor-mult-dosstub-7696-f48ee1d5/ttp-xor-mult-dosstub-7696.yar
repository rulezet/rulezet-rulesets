rule TTP_XOR_MULT_DOSStub_7696 {
  strings:
    $key_7696 = { 22 fe [2] 56 e6 [2] 11 e4 [2] 56 f5 [2] 18 f9 [2] 14 f3 [2] 03 f8 [2] 18 b6 [2] 25 }

  condition:
    any of them
}