rule TTP_XOR_MULT_DOSStub_02c0 {
  strings:
    $key_02c0 = { 56 a8 [2] 22 b0 [2] 65 b2 [2] 22 a3 [2] 6c af [2] 60 a5 [2] 77 ae [2] 6c e0 [2] 51 }

  condition:
    any of them
}