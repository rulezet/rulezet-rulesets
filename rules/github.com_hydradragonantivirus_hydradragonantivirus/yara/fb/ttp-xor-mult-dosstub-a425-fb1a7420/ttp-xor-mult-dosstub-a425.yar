rule TTP_XOR_MULT_DOSStub_a425 {
  strings:
    $key_a425 = { f0 4d [2] 84 55 [2] c3 57 [2] 84 46 [2] ca 4a [2] c6 40 [2] d1 4b [2] ca 05 [2] f7 }

  condition:
    any of them
}