rule TTP_XOR_MULT_DOSStub_65c7 {
  strings:
    $key_65c7 = { 31 af [2] 45 b7 [2] 02 b5 [2] 45 a4 [2] 0b a8 [2] 07 a2 [2] 10 a9 [2] 0b e7 [2] 36 }

  condition:
    any of them
}