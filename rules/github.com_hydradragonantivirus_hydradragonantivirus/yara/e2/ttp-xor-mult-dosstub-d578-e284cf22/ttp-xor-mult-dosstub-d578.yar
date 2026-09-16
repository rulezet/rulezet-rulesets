rule TTP_XOR_MULT_DOSStub_d578 {
  strings:
    $key_d578 = { 81 10 [2] f5 08 [2] b2 0a [2] f5 1b [2] bb 17 [2] b7 1d [2] a0 16 [2] bb 58 [2] 86 }

  condition:
    any of them
}