rule TTP_XOR_MULT_DOSStub_a4e2 {
  strings:
    $key_a4e2 = { f0 8a [2] 84 92 [2] c3 90 [2] 84 81 [2] ca 8d [2] c6 87 [2] d1 8c [2] ca c2 [2] f7 }

  condition:
    any of them
}