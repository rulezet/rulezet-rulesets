rule TTP_XOR_MULT_DOSStub_27c0 {
  strings:
    $key_27c0 = { 73 a8 [2] 07 b0 [2] 40 b2 [2] 07 a3 [2] 49 af [2] 45 a5 [2] 52 ae [2] 49 e0 [2] 74 }

  condition:
    any of them
}