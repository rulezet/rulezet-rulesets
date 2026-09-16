rule TTP_XOR_MULT_DOSStub_a602 {
  strings:
    $key_a602 = { f2 6a [2] 86 72 [2] c1 70 [2] 86 61 [2] c8 6d [2] c4 67 [2] d3 6c [2] c8 22 [2] f5 }

  condition:
    any of them
}