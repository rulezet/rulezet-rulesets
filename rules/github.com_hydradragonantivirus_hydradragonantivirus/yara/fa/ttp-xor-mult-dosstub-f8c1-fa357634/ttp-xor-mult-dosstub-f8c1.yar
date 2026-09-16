rule TTP_XOR_MULT_DOSStub_f8c1 {
  strings:
    $key_f8c1 = { ac a9 [2] d8 b1 [2] 9f b3 [2] d8 a2 [2] 96 ae [2] 9a a4 [2] 8d af [2] 96 e1 [2] ab }

  condition:
    any of them
}