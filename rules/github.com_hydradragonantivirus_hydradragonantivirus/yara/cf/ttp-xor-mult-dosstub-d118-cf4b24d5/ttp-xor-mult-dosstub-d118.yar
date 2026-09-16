rule TTP_XOR_MULT_DOSStub_d118 {
  strings:
    $key_d118 = { 85 70 [2] f1 68 [2] b6 6a [2] f1 7b [2] bf 77 [2] b3 7d [2] a4 76 [2] bf 38 [2] 82 }

  condition:
    any of them
}