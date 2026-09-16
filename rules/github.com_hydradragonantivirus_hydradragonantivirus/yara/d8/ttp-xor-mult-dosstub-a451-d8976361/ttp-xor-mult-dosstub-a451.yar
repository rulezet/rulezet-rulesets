rule TTP_XOR_MULT_DOSStub_a451 {
  strings:
    $key_a451 = { f0 39 [2] 84 21 [2] c3 23 [2] 84 32 [2] ca 3e [2] c6 34 [2] d1 3f [2] ca 71 [2] f7 }

  condition:
    any of them
}