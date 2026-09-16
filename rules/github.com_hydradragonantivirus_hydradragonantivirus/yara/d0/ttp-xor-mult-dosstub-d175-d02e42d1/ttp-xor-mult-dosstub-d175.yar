rule TTP_XOR_MULT_DOSStub_d175 {
  strings:
    $key_d175 = { 85 1d [2] f1 05 [2] b6 07 [2] f1 16 [2] bf 1a [2] b3 10 [2] a4 1b [2] bf 55 [2] 82 }

  condition:
    any of them
}