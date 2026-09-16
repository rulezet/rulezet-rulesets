rule TTP_XOR_MULT_DOSStub_f8c0 {
  strings:
    $key_f8c0 = { ac a8 [2] d8 b0 [2] 9f b2 [2] d8 a3 [2] 96 af [2] 9a a5 [2] 8d ae [2] 96 e0 [2] ab }

  condition:
    any of them
}