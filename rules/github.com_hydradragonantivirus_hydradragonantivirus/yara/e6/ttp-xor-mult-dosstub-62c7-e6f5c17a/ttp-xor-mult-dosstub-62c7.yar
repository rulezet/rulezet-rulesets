rule TTP_XOR_MULT_DOSStub_62c7 {
  strings:
    $key_62c7 = { 36 af [2] 42 b7 [2] 05 b5 [2] 42 a4 [2] 0c a8 [2] 00 a2 [2] 17 a9 [2] 0c e7 [2] 31 }

  condition:
    any of them
}