rule TTP_XOR_MULT_DOSStub_a445 {
  strings:
    $key_a445 = { f0 2d [2] 84 35 [2] c3 37 [2] 84 26 [2] ca 2a [2] c6 20 [2] d1 2b [2] ca 65 [2] f7 }

  condition:
    any of them
}