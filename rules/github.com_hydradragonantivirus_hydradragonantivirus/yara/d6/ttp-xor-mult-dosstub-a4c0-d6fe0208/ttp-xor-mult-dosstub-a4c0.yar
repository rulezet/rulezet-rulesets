rule TTP_XOR_MULT_DOSStub_a4c0 {
  strings:
    $key_a4c0 = { f0 a8 [2] 84 b0 [2] c3 b2 [2] 84 a3 [2] ca af [2] c6 a5 [2] d1 ae [2] ca e0 [2] f7 }

  condition:
    any of them
}