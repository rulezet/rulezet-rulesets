rule TTP_XOR_MULT_DOSStub_a0f1 {
  strings:
    $key_a0f1 = { f4 99 [2] 80 81 [2] c7 83 [2] 80 92 [2] ce 9e [2] c2 94 [2] d5 9f [2] ce d1 [2] f3 }

  condition:
    any of them
}