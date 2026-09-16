rule TTP_XOR_MULT_DOSStub_f8a7 {
  strings:
    $key_f8a7 = { ac cf [2] d8 d7 [2] 9f d5 [2] d8 c4 [2] 96 c8 [2] 9a c2 [2] 8d c9 [2] 96 87 [2] ab }

  condition:
    any of them
}