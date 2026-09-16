rule TTP_XOR_MULT_DOSStub_d17c {
  strings:
    $key_d17c = { 85 14 [2] f1 0c [2] b6 0e [2] f1 1f [2] bf 13 [2] b3 19 [2] a4 12 [2] bf 5c [2] 82 }

  condition:
    any of them
}