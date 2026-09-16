rule TTP_XOR_MULT_DOSStub_f4ac {
  strings:
    $key_f4ac = { a0 c4 [2] d4 dc [2] 93 de [2] d4 cf [2] 9a c3 [2] 96 c9 [2] 81 c2 [2] 9a 8c [2] a7 }

  condition:
    any of them
}