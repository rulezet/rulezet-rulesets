rule TTP_XOR_MULT_DOSStub_d0c5 {
  strings:
    $key_d0c5 = { 84 ad [2] f0 b5 [2] b7 b7 [2] f0 a6 [2] be aa [2] b2 a0 [2] a5 ab [2] be e5 [2] 83 }

  condition:
    any of them
}