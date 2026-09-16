rule TTP_XOR_MULT_DOSStub_33c0 {
  strings:
    $key_33c0 = { 67 a8 [2] 13 b0 [2] 54 b2 [2] 13 a3 [2] 5d af [2] 51 a5 [2] 46 ae [2] 5d e0 [2] 60 }

  condition:
    any of them
}