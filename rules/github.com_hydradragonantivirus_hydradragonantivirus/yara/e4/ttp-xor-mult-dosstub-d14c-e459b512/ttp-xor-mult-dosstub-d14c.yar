rule TTP_XOR_MULT_DOSStub_d14c {
  strings:
    $key_d14c = { 85 24 [2] f1 3c [2] b6 3e [2] f1 2f [2] bf 23 [2] b3 29 [2] a4 22 [2] bf 6c [2] 82 }

  condition:
    any of them
}