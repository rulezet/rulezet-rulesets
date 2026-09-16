rule TTP_XOR_MULT_DOSStub_d44a {
  strings:
    $key_d44a = { 80 22 [2] f4 3a [2] b3 38 [2] f4 29 [2] ba 25 [2] b6 2f [2] a1 24 [2] ba 6a [2] 87 }

  condition:
    any of them
}