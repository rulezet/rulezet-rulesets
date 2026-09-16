rule TTP_XOR_MULT_DOSStub_d746 {
  strings:
    $key_d746 = { 83 2e [2] f7 36 [2] b0 34 [2] f7 25 [2] b9 29 [2] b5 23 [2] a2 28 [2] b9 66 [2] 84 }

  condition:
    any of them
}