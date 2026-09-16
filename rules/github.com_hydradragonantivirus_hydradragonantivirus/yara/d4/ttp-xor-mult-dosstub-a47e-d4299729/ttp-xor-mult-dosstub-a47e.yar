rule TTP_XOR_MULT_DOSStub_a47e {
  strings:
    $key_a47e = { f0 16 [2] 84 0e [2] c3 0c [2] 84 1d [2] ca 11 [2] c6 1b [2] d1 10 [2] ca 5e [2] f7 }

  condition:
    any of them
}