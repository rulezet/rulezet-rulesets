rule TTP_XOR_MULT_DOSStub_d868 {
  strings:
    $key_d868 = { 8c 00 [2] f8 18 [2] bf 1a [2] f8 0b [2] b6 07 [2] ba 0d [2] ad 06 [2] b6 48 [2] 8b }

  condition:
    any of them
}