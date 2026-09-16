rule TTP_XOR_MULT_DOSStub_a081 {
  strings:
    $key_a081 = { f4 e9 [2] 80 f1 [2] c7 f3 [2] 80 e2 [2] ce ee [2] c2 e4 [2] d5 ef [2] ce a1 [2] f3 }

  condition:
    any of them
}