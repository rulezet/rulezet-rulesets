rule TTP_XOR_MULT_DOSStub_d39b {
  strings:
    $key_d39b = { 87 f3 [2] f3 eb [2] b4 e9 [2] f3 f8 [2] bd f4 [2] b1 fe [2] a6 f5 [2] bd bb [2] 80 }

  condition:
    any of them
}