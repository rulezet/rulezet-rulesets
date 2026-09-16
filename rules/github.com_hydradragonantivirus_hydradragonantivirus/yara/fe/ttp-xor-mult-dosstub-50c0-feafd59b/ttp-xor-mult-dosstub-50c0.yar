rule TTP_XOR_MULT_DOSStub_50c0 {
  strings:
    $key_50c0 = { 04 a8 [2] 70 b0 [2] 37 b2 [2] 70 a3 [2] 3e af [2] 32 a5 [2] 25 ae [2] 3e e0 [2] 03 }

  condition:
    any of them
}