rule TTP_XOR_MULT_DOSStub_65c0 {
  strings:
    $key_65c0 = { 31 a8 [2] 45 b0 [2] 02 b2 [2] 45 a3 [2] 0b af [2] 07 a5 [2] 10 ae [2] 0b e0 [2] 36 }

  condition:
    any of them
}