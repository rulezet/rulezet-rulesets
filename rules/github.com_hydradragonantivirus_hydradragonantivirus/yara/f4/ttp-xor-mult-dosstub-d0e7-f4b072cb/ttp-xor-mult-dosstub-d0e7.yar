rule TTP_XOR_MULT_DOSStub_d0e7 {
  strings:
    $key_d0e7 = { 84 8f [2] f0 97 [2] b7 95 [2] f0 84 [2] be 88 [2] b2 82 [2] a5 89 [2] be c7 [2] 83 }

  condition:
    any of them
}