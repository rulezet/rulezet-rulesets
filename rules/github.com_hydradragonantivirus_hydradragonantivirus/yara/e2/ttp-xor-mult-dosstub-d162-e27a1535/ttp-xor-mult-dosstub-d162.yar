rule TTP_XOR_MULT_DOSStub_d162 {
  strings:
    $key_d162 = { 85 0a [2] f1 12 [2] b6 10 [2] f1 01 [2] bf 0d [2] b3 07 [2] a4 0c [2] bf 42 [2] 82 }

  condition:
    any of them
}