rule TTP_XOR_MULT_DOSStub_a44b {
  strings:
    $key_a44b = { f0 23 [2] 84 3b [2] c3 39 [2] 84 28 [2] ca 24 [2] c6 2e [2] d1 25 [2] ca 6b [2] f7 }

  condition:
    any of them
}