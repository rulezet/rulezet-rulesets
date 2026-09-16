rule TTP_XOR_MULT_DOSStub_a469 {
  strings:
    $key_a469 = { f0 01 [2] 84 19 [2] c3 1b [2] 84 0a [2] ca 06 [2] c6 0c [2] d1 07 [2] ca 49 [2] f7 }

  condition:
    any of them
}