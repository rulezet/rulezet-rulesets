rule TTP_XOR_MULT_DOSStub_d528 {
  strings:
    $key_d528 = { 81 40 [2] f5 58 [2] b2 5a [2] f5 4b [2] bb 47 [2] b7 4d [2] a0 46 [2] bb 08 [2] 86 }

  condition:
    any of them
}