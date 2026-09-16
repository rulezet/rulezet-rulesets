rule TTP_XOR_MULT_DOSStub_a473 {
  strings:
    $key_a473 = { f0 1b [2] 84 03 [2] c3 01 [2] 84 10 [2] ca 1c [2] c6 16 [2] d1 1d [2] ca 53 [2] f7 }

  condition:
    any of them
}