rule TTP_XOR_MULT_DOSStub_d859 {
  strings:
    $key_d859 = { 8c 31 [2] f8 29 [2] bf 2b [2] f8 3a [2] b6 36 [2] ba 3c [2] ad 37 [2] b6 79 [2] 8b }

  condition:
    any of them
}