rule TTP_XOR_MULT_DOSStub_d138 {
  strings:
    $key_d138 = { 85 50 [2] f1 48 [2] b6 4a [2] f1 5b [2] bf 57 [2] b3 5d [2] a4 56 [2] bf 18 [2] 82 }

  condition:
    any of them
}