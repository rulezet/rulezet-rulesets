rule TTP_XOR_MULT_DOSStub_19c1 {
  strings:
    $key_19c1 = { 4d a9 [2] 39 b1 [2] 7e b3 [2] 39 a2 [2] 77 ae [2] 7b a4 [2] 6c af [2] 77 e1 [2] 4a }

  condition:
    any of them
}