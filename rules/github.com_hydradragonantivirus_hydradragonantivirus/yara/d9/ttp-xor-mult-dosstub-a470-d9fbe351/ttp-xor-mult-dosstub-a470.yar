rule TTP_XOR_MULT_DOSStub_a470 {
  strings:
    $key_a470 = { f0 18 [2] 84 00 [2] c3 02 [2] 84 13 [2] ca 1f [2] c6 15 [2] d1 1e [2] ca 50 [2] f7 }

  condition:
    any of them
}