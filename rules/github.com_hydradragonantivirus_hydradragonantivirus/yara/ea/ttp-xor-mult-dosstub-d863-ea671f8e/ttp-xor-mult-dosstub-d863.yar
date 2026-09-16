rule TTP_XOR_MULT_DOSStub_d863 {
  strings:
    $key_d863 = { 8c 0b [2] f8 13 [2] bf 11 [2] f8 00 [2] b6 0c [2] ba 06 [2] ad 0d [2] b6 43 [2] 8b }

  condition:
    any of them
}