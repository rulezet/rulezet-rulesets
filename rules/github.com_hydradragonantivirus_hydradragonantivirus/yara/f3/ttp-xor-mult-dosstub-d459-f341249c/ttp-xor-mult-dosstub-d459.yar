rule TTP_XOR_MULT_DOSStub_d459 {
  strings:
    $key_d459 = { 80 31 [2] f4 29 [2] b3 2b [2] f4 3a [2] ba 36 [2] b6 3c [2] a1 37 [2] ba 79 [2] 87 }

  condition:
    any of them
}