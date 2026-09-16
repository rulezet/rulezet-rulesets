rule TTP_XOR_MULT_DOSStub_d818 {
  strings:
    $key_d818 = { 8c 70 [2] f8 68 [2] bf 6a [2] f8 7b [2] b6 77 [2] ba 7d [2] ad 76 [2] b6 38 [2] 8b }

  condition:
    any of them
}