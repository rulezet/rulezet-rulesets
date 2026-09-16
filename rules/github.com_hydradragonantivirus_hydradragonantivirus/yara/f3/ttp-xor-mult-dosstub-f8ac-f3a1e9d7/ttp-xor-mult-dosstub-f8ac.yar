rule TTP_XOR_MULT_DOSStub_f8ac {
  strings:
    $key_f8ac = { ac c4 [2] d8 dc [2] 9f de [2] d8 cf [2] 96 c3 [2] 9a c9 [2] 8d c2 [2] 96 8c [2] ab }

  condition:
    any of them
}