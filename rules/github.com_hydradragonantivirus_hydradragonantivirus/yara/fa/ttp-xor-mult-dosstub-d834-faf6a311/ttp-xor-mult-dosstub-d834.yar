rule TTP_XOR_MULT_DOSStub_d834 {
  strings:
    $key_d834 = { 8c 5c [2] f8 44 [2] bf 46 [2] f8 57 [2] b6 5b [2] ba 51 [2] ad 5a [2] b6 14 [2] 8b }

  condition:
    any of them
}