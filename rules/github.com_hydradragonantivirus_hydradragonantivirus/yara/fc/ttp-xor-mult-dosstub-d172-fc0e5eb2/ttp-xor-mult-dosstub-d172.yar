rule TTP_XOR_MULT_DOSStub_d172 {
  strings:
    $key_d172 = { 85 1a [2] f1 02 [2] b6 00 [2] f1 11 [2] bf 1d [2] b3 17 [2] a4 1c [2] bf 52 [2] 82 }

  condition:
    any of them
}