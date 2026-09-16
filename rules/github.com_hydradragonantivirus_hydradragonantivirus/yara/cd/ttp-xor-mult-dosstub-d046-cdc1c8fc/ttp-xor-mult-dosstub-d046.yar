rule TTP_XOR_MULT_DOSStub_d046 {
  strings:
    $key_d046 = { 84 2e [2] f0 36 [2] b7 34 [2] f0 25 [2] be 29 [2] b2 23 [2] a5 28 [2] be 66 [2] 83 }

  condition:
    any of them
}