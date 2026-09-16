rule TTP_XOR_MULT_DOSStub_31c0 {
  strings:
    $key_31c0 = { 65 a8 [2] 11 b0 [2] 56 b2 [2] 11 a3 [2] 5f af [2] 53 a5 [2] 44 ae [2] 5f e0 [2] 62 }

  condition:
    any of them
}