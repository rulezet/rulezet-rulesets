rule TTP_XOR_MULT_DOSStub_11c1 {
  strings:
    $key_11c1 = { 45 a9 [2] 31 b1 [2] 76 b3 [2] 31 a2 [2] 7f ae [2] 73 a4 [2] 64 af [2] 7f e1 [2] 42 }

  condition:
    any of them
}