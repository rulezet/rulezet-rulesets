rule TTP_XOR_MULT_DOSStub_d041 {
  strings:
    $key_d041 = { 84 29 [2] f0 31 [2] b7 33 [2] f0 22 [2] be 2e [2] b2 24 [2] a5 2f [2] be 61 [2] 83 }

  condition:
    any of them
}