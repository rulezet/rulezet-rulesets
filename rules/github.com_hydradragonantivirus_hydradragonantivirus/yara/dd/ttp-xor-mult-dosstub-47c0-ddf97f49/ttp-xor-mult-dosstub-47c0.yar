rule TTP_XOR_MULT_DOSStub_47c0 {
  strings:
    $key_47c0 = { 13 a8 [2] 67 b0 [2] 20 b2 [2] 67 a3 [2] 29 af [2] 25 a5 [2] 32 ae [2] 29 e0 [2] 14 }

  condition:
    any of them
}