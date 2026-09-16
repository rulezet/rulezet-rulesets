rule TTP_XOR_MULT_DOSStub_d16f {
  strings:
    $key_d16f = { 85 07 [2] f1 1f [2] b6 1d [2] f1 0c [2] bf 00 [2] b3 0a [2] a4 01 [2] bf 4f [2] 82 }

  condition:
    any of them
}