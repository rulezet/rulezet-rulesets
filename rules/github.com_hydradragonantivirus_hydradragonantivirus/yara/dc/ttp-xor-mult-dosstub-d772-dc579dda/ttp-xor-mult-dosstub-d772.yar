rule TTP_XOR_MULT_DOSStub_d772 {
  strings:
    $key_d772 = { 83 1a [2] f7 02 [2] b0 00 [2] f7 11 [2] b9 1d [2] b5 17 [2] a2 1c [2] b9 52 [2] 84 }

  condition:
    any of them
}