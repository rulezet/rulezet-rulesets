rule TTP_XOR_MULT_DOSStub_24c1 {
  strings:
    $key_24c1 = { 70 a9 [2] 04 b1 [2] 43 b3 [2] 04 a2 [2] 4a ae [2] 46 a4 [2] 51 af [2] 4a e1 [2] 77 }

  condition:
    any of them
}