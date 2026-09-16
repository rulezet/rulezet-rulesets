rule TTP_XOR_MULT_DOSStub_63c0 {
  strings:
    $key_63c0 = { 37 a8 [2] 43 b0 [2] 04 b2 [2] 43 a3 [2] 0d af [2] 01 a5 [2] 16 ae [2] 0d e0 [2] 30 }

  condition:
    any of them
}