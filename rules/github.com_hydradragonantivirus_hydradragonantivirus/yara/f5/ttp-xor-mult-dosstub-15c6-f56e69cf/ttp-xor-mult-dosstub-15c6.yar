rule TTP_XOR_MULT_DOSStub_15c6 {
  strings:
    $key_15c6 = { 41 ae [2] 35 b6 [2] 72 b4 [2] 35 a5 [2] 7b a9 [2] 77 a3 [2] 60 a8 [2] 7b e6 [2] 46 }

  condition:
    any of them
}