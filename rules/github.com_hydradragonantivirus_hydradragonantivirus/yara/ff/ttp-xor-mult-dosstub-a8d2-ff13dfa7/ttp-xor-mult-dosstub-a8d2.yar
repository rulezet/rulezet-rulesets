rule TTP_XOR_MULT_DOSStub_a8d2 {
  strings:
    $key_a8d2 = { fc ba [2] 88 a2 [2] cf a0 [2] 88 b1 [2] c6 bd [2] ca b7 [2] dd bc [2] c6 f2 [2] fb }

  condition:
    any of them
}