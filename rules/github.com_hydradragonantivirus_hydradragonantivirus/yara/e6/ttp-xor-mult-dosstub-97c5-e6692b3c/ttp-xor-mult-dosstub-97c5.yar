rule TTP_XOR_MULT_DOSStub_97c5 {
  strings:
    $key_97c5 = { c3 ad [2] b7 b5 [2] f0 b7 [2] b7 a6 [2] f9 aa [2] f5 a0 [2] e2 ab [2] f9 e5 [2] c4 }

  condition:
    any of them
}