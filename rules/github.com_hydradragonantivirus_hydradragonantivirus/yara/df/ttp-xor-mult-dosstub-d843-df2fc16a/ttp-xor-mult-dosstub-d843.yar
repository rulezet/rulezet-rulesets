rule TTP_XOR_MULT_DOSStub_d843 {
  strings:
    $key_d843 = { 8c 2b [2] f8 33 [2] bf 31 [2] f8 20 [2] b6 2c [2] ba 26 [2] ad 2d [2] b6 63 [2] 8b }

  condition:
    any of them
}