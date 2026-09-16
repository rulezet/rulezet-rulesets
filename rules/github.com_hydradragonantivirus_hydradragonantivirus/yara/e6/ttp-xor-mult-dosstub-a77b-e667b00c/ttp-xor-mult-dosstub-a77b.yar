rule TTP_XOR_MULT_DOSStub_a77b {
  strings:
    $key_a77b = { f3 13 [2] 87 0b [2] c0 09 [2] 87 18 [2] c9 14 [2] c5 1e [2] d2 15 [2] c9 5b [2] f4 }

  condition:
    any of them
}