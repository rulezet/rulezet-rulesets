rule TTP_XOR_MULT_DOSStub_d7f0 {
  strings:
    $key_d7f0 = { 83 98 [2] f7 80 [2] b0 82 [2] f7 93 [2] b9 9f [2] b5 95 [2] a2 9e [2] b9 d0 [2] 84 }

  condition:
    any of them
}