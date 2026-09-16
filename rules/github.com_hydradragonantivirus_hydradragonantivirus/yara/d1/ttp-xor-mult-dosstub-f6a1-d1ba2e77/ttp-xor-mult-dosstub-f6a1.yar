rule TTP_XOR_MULT_DOSStub_f6a1 {
  strings:
    $key_f6a1 = { a2 c9 [2] d6 d1 [2] 91 d3 [2] d6 c2 [2] 98 ce [2] 94 c4 [2] 83 cf [2] 98 81 [2] a5 }

  condition:
    any of them
}