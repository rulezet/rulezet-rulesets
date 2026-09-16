rule TTP_XOR_MULT_DOSStub_d45a {
  strings:
    $key_d45a = { 80 32 [2] f4 2a [2] b3 28 [2] f4 39 [2] ba 35 [2] b6 3f [2] a1 34 [2] ba 7a [2] 87 }

  condition:
    any of them
}