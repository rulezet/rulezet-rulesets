rule TTP_XOR_MULT_DOSStub_a462 {
  strings:
    $key_a462 = { f0 0a [2] 84 12 [2] c3 10 [2] 84 01 [2] ca 0d [2] c6 07 [2] d1 0c [2] ca 42 [2] f7 }

  condition:
    any of them
}