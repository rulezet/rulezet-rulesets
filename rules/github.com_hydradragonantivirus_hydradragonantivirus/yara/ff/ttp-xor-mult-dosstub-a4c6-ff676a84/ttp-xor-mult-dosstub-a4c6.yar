rule TTP_XOR_MULT_DOSStub_a4c6 {
  strings:
    $key_a4c6 = { f0 ae [2] 84 b6 [2] c3 b4 [2] 84 a5 [2] ca a9 [2] c6 a3 [2] d1 a8 [2] ca e6 [2] f7 }

  condition:
    any of them
}