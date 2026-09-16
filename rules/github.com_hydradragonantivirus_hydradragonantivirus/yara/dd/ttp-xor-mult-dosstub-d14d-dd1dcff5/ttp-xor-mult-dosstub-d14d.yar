rule TTP_XOR_MULT_DOSStub_d14d {
  strings:
    $key_d14d = { 85 25 [2] f1 3d [2] b6 3f [2] f1 2e [2] bf 22 [2] b3 28 [2] a4 23 [2] bf 6d [2] 82 }

  condition:
    any of them
}