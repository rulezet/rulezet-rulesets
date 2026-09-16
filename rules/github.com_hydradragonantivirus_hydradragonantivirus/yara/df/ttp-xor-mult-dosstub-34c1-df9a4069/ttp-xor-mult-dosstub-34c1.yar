rule TTP_XOR_MULT_DOSStub_34c1 {
  strings:
    $key_34c1 = { 60 a9 [2] 14 b1 [2] 53 b3 [2] 14 a2 [2] 5a ae [2] 56 a4 [2] 41 af [2] 5a e1 [2] 67 }

  condition:
    any of them
}