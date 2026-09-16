rule TTP_XOR_MULT_DOSStub_d1f7 {
  strings:
    $key_d1f7 = { 85 9f [2] f1 87 [2] b6 85 [2] f1 94 [2] bf 98 [2] b3 92 [2] a4 99 [2] bf d7 [2] 82 }

  condition:
    any of them
}