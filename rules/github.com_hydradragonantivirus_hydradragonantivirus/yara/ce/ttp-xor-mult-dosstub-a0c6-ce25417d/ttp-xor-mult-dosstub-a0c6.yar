rule TTP_XOR_MULT_DOSStub_a0c6 {
  strings:
    $key_a0c6 = { f4 ae [2] 80 b6 [2] c7 b4 [2] 80 a5 [2] ce a9 [2] c2 a3 [2] d5 a8 [2] ce e6 [2] f3 }

  condition:
    any of them
}