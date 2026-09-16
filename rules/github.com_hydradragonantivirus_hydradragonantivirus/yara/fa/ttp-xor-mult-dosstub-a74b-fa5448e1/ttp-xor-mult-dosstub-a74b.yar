rule TTP_XOR_MULT_DOSStub_a74b {
  strings:
    $key_a74b = { f3 23 [2] 87 3b [2] c0 39 [2] 87 28 [2] c9 24 [2] c5 2e [2] d2 25 [2] c9 6b [2] f4 }

  condition:
    any of them
}