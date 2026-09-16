rule TTP_XOR_MULT_DOSStub_f3a7 {
  strings:
    $key_f3a7 = { a7 cf [2] d3 d7 [2] 94 d5 [2] d3 c4 [2] 9d c8 [2] 91 c2 [2] 86 c9 [2] 9d 87 [2] a0 }

  condition:
    any of them
}