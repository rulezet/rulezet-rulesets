rule TTP_XOR_MULT_DOSStub_a1f3 {
  strings:
    $key_a1f3 = { f5 9b [2] 81 83 [2] c6 81 [2] 81 90 [2] cf 9c [2] c3 96 [2] d4 9d [2] cf d3 [2] f2 }

  condition:
    any of them
}