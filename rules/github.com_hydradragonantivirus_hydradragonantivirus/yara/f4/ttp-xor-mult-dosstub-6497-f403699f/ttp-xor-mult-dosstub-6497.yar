rule TTP_XOR_MULT_DOSStub_6497 {
  strings:
    $key_6497 = { 30 ff [2] 44 e7 [2] 03 e5 [2] 44 f4 [2] 0a f8 [2] 06 f2 [2] 11 f9 [2] 0a b7 [2] 37 }

  condition:
    any of them
}