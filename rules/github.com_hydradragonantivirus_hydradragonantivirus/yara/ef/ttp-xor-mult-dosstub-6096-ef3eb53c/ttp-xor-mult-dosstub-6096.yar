rule TTP_XOR_MULT_DOSStub_6096 {
  strings:
    $key_6096 = { 34 fe [2] 40 e6 [2] 07 e4 [2] 40 f5 [2] 0e f9 [2] 02 f3 [2] 15 f8 [2] 0e b6 [2] 33 }

  condition:
    any of them
}