rule TTP_XOR_MULT_DOSStub_a461 {
  strings:
    $key_a461 = { f0 09 [2] 84 11 [2] c3 13 [2] 84 02 [2] ca 0e [2] c6 04 [2] d1 0f [2] ca 41 [2] f7 }

  condition:
    any of them
}