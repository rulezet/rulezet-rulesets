rule TTP_XOR_MULT_DOSStub_d444 {
  strings:
    $key_d444 = { 80 2c [2] f4 34 [2] b3 36 [2] f4 27 [2] ba 2b [2] b6 21 [2] a1 2a [2] ba 64 [2] 87 }

  condition:
    any of them
}