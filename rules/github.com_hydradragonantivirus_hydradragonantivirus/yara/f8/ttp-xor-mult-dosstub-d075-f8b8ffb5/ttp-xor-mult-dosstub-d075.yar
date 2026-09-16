rule TTP_XOR_MULT_DOSStub_d075 {
  strings:
    $key_d075 = { 84 1d [2] f0 05 [2] b7 07 [2] f0 16 [2] be 1a [2] b2 10 [2] a5 1b [2] be 55 [2] 83 }

  condition:
    any of them
}