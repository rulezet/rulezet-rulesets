rule TTP_XOR_MULT_DOSStub_f8a1 {
  strings:
    $key_f8a1 = { ac c9 [2] d8 d1 [2] 9f d3 [2] d8 c2 [2] 96 ce [2] 9a c4 [2] 8d cf [2] 96 81 [2] ab }

  condition:
    any of them
}