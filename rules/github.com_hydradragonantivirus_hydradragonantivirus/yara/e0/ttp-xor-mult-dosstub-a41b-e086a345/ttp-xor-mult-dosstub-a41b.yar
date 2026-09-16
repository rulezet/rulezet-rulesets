rule TTP_XOR_MULT_DOSStub_a41b {
  strings:
    $key_a41b = { f0 73 [2] 84 6b [2] c3 69 [2] 84 78 [2] ca 74 [2] c6 7e [2] d1 75 [2] ca 3b [2] f7 }

  condition:
    any of them
}