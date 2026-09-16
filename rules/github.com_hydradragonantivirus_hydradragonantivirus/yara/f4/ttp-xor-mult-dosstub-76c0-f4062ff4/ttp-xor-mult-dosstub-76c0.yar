rule TTP_XOR_MULT_DOSStub_76c0 {
  strings:
    $key_76c0 = { 22 a8 [2] 56 b0 [2] 11 b2 [2] 56 a3 [2] 18 af [2] 14 a5 [2] 03 ae [2] 18 e0 [2] 25 }

  condition:
    any of them
}