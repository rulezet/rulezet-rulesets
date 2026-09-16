rule TTP_XOR_MULT_DOSStub_d574 {
  strings:
    $key_d574 = { 81 1c [2] f5 04 [2] b2 06 [2] f5 17 [2] bb 1b [2] b7 11 [2] a0 1a [2] bb 54 [2] 86 }

  condition:
    any of them
}