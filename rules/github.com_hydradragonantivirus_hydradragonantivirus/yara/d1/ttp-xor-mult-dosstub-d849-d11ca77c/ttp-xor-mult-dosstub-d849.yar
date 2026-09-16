rule TTP_XOR_MULT_DOSStub_d849 {
  strings:
    $key_d849 = { 8c 21 [2] f8 39 [2] bf 3b [2] f8 2a [2] b6 26 [2] ba 2c [2] ad 27 [2] b6 69 [2] 8b }

  condition:
    any of them
}