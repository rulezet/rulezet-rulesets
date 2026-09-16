rule TTP_XOR_MULT_DOSStub_a449 {
  strings:
    $key_a449 = { f0 21 [2] 84 39 [2] c3 3b [2] 84 2a [2] ca 26 [2] c6 2c [2] d1 27 [2] ca 69 [2] f7 }

  condition:
    any of them
}