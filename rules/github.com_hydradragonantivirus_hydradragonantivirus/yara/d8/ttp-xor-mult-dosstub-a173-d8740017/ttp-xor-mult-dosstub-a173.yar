rule TTP_XOR_MULT_DOSStub_a173 {
  strings:
    $key_a173 = { f5 1b [2] 81 03 [2] c6 01 [2] 81 10 [2] cf 1c [2] c3 16 [2] d4 1d [2] cf 53 [2] f2 }

  condition:
    any of them
}