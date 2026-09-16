rule TTP_XOR_MULT_DOSStub_a414 {
  strings:
    $key_a414 = { f0 7c [2] 84 64 [2] c3 66 [2] 84 77 [2] ca 7b [2] c6 71 [2] d1 7a [2] ca 34 [2] f7 }

  condition:
    any of them
}