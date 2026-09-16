rule TTP_XOR_MULT_DOSStub_d15b {
  strings:
    $key_d15b = { 85 33 [2] f1 2b [2] b6 29 [2] f1 38 [2] bf 34 [2] b3 3e [2] a4 35 [2] bf 7b [2] 82 }

  condition:
    any of them
}