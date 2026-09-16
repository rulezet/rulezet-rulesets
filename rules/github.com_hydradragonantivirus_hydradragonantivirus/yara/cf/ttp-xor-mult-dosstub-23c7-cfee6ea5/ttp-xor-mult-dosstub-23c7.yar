rule TTP_XOR_MULT_DOSStub_23c7 {
  strings:
    $key_23c7 = { 77 af [2] 03 b7 [2] 44 b5 [2] 03 a4 [2] 4d a8 [2] 41 a2 [2] 56 a9 [2] 4d e7 [2] 70 }

  condition:
    any of them
}