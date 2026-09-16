rule TTP_XOR_MULT_DOSStub_92f0 {
  strings:
    $key_92f0 = { c6 98 [2] b2 80 [2] f5 82 [2] b2 93 [2] fc 9f [2] f0 95 [2] e7 9e [2] fc d0 [2] c1 }

  condition:
    any of them
}