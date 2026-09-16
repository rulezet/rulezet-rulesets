rule TTP_XOR_MULT_DOSStub_34d7 {
  strings:
    $key_34d7 = { 60 bf [2] 14 a7 [2] 53 a5 [2] 14 b4 [2] 5a b8 [2] 56 b2 [2] 41 b9 [2] 5a f7 [2] 67 }

  condition:
    any of them
}