rule TTP_XOR_MULT_DOSStub_37c1 {
  strings:
    $key_37c1 = { 63 a9 [2] 17 b1 [2] 50 b3 [2] 17 a2 [2] 59 ae [2] 55 a4 [2] 42 af [2] 59 e1 [2] 64 }

  condition:
    any of them
}