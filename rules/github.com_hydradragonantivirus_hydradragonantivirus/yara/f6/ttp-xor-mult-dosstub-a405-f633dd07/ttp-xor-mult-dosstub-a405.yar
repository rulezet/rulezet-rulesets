rule TTP_XOR_MULT_DOSStub_a405 {
  strings:
    $key_a405 = { f0 6d [2] 84 75 [2] c3 77 [2] 84 66 [2] ca 6a [2] c6 60 [2] d1 6b [2] ca 25 [2] f7 }

  condition:
    any of them
}