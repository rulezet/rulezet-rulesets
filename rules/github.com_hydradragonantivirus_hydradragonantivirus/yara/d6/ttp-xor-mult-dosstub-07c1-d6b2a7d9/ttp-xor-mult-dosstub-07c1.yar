rule TTP_XOR_MULT_DOSStub_07c1 {
  strings:
    $key_07c1 = { 53 a9 [2] 27 b1 [2] 60 b3 [2] 27 a2 [2] 69 ae [2] 65 a4 [2] 72 af [2] 69 e1 [2] 54 }

  condition:
    any of them
}