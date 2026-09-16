rule TTP_XOR_MULT_DOSStub_d1fa {
  strings:
    $key_d1fa = { 85 92 [2] f1 8a [2] b6 88 [2] f1 99 [2] bf 95 [2] b3 9f [2] a4 94 [2] bf da [2] 82 }

  condition:
    any of them
}