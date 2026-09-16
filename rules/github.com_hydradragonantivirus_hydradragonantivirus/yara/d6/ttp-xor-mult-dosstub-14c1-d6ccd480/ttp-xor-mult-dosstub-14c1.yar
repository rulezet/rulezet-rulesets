rule TTP_XOR_MULT_DOSStub_14c1 {
  strings:
    $key_14c1 = { 40 a9 [2] 34 b1 [2] 73 b3 [2] 34 a2 [2] 7a ae [2] 76 a4 [2] 61 af [2] 7a e1 [2] 47 }

  condition:
    any of them
}