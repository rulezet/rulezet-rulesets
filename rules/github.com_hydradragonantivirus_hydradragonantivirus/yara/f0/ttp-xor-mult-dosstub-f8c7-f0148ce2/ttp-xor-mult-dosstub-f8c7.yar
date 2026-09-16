rule TTP_XOR_MULT_DOSStub_f8c7 {
  strings:
    $key_f8c7 = { ac af [2] d8 b7 [2] 9f b5 [2] d8 a4 [2] 96 a8 [2] 9a a2 [2] 8d a9 [2] 96 e7 [2] ab }

  condition:
    any of them
}