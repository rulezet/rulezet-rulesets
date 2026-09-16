rule TTP_XOR_MULT_DOSStub_d144 {
  strings:
    $key_d144 = { 85 2c [2] f1 34 [2] b6 36 [2] f1 27 [2] bf 2b [2] b3 21 [2] a4 2a [2] bf 64 [2] 82 }

  condition:
    any of them
}