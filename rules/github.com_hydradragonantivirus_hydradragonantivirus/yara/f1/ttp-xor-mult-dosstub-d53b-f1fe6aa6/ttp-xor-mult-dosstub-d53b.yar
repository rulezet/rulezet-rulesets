rule TTP_XOR_MULT_DOSStub_d53b {
  strings:
    $key_d53b = { 81 53 [2] f5 4b [2] b2 49 [2] f5 58 [2] bb 54 [2] b7 5e [2] a0 55 [2] bb 1b [2] 86 }

  condition:
    any of them
}