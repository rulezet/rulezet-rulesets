rule TTP_XOR_MULT_DOSStub_a0d2 {
  strings:
    $key_a0d2 = { f4 ba [2] 80 a2 [2] c7 a0 [2] 80 b1 [2] ce bd [2] c2 b7 [2] d5 bc [2] ce f2 [2] f3 }

  condition:
    any of them
}