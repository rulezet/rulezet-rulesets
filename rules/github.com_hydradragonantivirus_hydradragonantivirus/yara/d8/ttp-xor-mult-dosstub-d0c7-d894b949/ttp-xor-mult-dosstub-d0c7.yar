rule TTP_XOR_MULT_DOSStub_d0c7 {
  strings:
    $key_d0c7 = { 84 af [2] f0 b7 [2] b7 b5 [2] f0 a4 [2] be a8 [2] b2 a2 [2] a5 a9 [2] be e7 [2] 83 }

  condition:
    any of them
}