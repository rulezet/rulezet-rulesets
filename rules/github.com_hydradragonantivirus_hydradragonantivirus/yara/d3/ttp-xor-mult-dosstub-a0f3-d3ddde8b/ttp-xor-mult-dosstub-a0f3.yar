rule TTP_XOR_MULT_DOSStub_a0f3 {
  strings:
    $key_a0f3 = { f4 9b [2] 80 83 [2] c7 81 [2] 80 90 [2] ce 9c [2] c2 96 [2] d5 9d [2] ce d3 [2] f3 }

  condition:
    any of them
}