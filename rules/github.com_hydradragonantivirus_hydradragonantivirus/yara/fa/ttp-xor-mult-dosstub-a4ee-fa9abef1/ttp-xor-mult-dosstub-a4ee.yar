rule TTP_XOR_MULT_DOSStub_a4ee {
  strings:
    $key_a4ee = { f0 86 [2] 84 9e [2] c3 9c [2] 84 8d [2] ca 81 [2] c6 8b [2] d1 80 [2] ca ce [2] f7 }

  condition:
    any of them
}