rule TTP_XOR_MULT_DOSStub_a7bc {
  strings:
    $key_a7bc = { f3 d4 [2] 87 cc [2] c0 ce [2] 87 df [2] c9 d3 [2] c5 d9 [2] d2 d2 [2] c9 9c [2] f4 }

  condition:
    any of them
}