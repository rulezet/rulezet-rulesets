rule TTP_XOR_MULT_DOSStub_09c1 {
  strings:
    $key_09c1 = { 5d a9 [2] 29 b1 [2] 6e b3 [2] 29 a2 [2] 67 ae [2] 6b a4 [2] 7c af [2] 67 e1 [2] 5a }

  condition:
    any of them
}