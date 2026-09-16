rule TTP_XOR_MULT_DOSStub_a434 {
  strings:
    $key_a434 = { f0 5c [2] 84 44 [2] c3 46 [2] 84 57 [2] ca 5b [2] c6 51 [2] d1 5a [2] ca 14 [2] f7 }

  condition:
    any of them
}