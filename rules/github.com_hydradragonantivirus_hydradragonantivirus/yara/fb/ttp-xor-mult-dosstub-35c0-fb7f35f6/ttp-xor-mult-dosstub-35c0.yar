rule TTP_XOR_MULT_DOSStub_35c0 {
  strings:
    $key_35c0 = { 61 a8 [2] 15 b0 [2] 52 b2 [2] 15 a3 [2] 5b af [2] 57 a5 [2] 40 ae [2] 5b e0 [2] 66 }

  condition:
    any of them
}