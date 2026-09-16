rule TTP_XOR_MULT_DOSStub_05c0 {
  strings:
    $key_05c0 = { 51 a8 [2] 25 b0 [2] 62 b2 [2] 25 a3 [2] 6b af [2] 67 a5 [2] 70 ae [2] 6b e0 [2] 56 }

  condition:
    any of them
}