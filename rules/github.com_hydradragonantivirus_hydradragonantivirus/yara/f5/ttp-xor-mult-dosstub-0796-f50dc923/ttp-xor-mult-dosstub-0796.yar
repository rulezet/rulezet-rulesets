rule TTP_XOR_MULT_DOSStub_0796 {
  strings:
    $key_0796 = { 53 fe [2] 27 e6 [2] 60 e4 [2] 27 f5 [2] 69 f9 [2] 65 f3 [2] 72 f8 [2] 69 b6 [2] 54 }

  condition:
    any of them
}