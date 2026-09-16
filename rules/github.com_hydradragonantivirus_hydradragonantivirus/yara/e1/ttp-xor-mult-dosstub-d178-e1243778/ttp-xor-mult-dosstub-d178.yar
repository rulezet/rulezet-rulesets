rule TTP_XOR_MULT_DOSStub_d178 {
  strings:
    $key_d178 = { 85 10 [2] f1 08 [2] b6 0a [2] f1 1b [2] bf 17 [2] b3 1d [2] a4 16 [2] bf 58 [2] 82 }

  condition:
    any of them
}