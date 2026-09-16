rule TTP_XOR_MULT_DOSStub_3497 {
  strings:
    $key_3497 = { 60 ff [2] 14 e7 [2] 53 e5 [2] 14 f4 [2] 5a f8 [2] 56 f2 [2] 41 f9 [2] 5a b7 [2] 67 }

  condition:
    any of them
}