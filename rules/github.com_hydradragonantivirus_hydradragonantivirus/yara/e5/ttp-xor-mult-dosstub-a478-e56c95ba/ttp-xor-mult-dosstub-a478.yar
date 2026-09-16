rule TTP_XOR_MULT_DOSStub_a478 {
  strings:
    $key_a478 = { f0 10 [2] 84 08 [2] c3 0a [2] 84 1b [2] ca 17 [2] c6 1d [2] d1 16 [2] ca 58 [2] f7 }

  condition:
    any of them
}