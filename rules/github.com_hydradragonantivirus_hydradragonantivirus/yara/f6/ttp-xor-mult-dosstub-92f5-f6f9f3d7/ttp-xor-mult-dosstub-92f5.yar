rule TTP_XOR_MULT_DOSStub_92f5 {
  strings:
    $key_92f5 = { c6 9d [2] b2 85 [2] f5 87 [2] b2 96 [2] fc 9a [2] f0 90 [2] e7 9b [2] fc d5 [2] c1 }

  condition:
    any of them
}