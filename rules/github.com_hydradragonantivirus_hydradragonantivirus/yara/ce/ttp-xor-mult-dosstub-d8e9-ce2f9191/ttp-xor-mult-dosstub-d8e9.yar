rule TTP_XOR_MULT_DOSStub_d8e9 {
  strings:
    $key_d8e9 = { 8c 81 [2] f8 99 [2] bf 9b [2] f8 8a [2] b6 86 [2] ba 8c [2] ad 87 [2] b6 c9 [2] 8b }

  condition:
    any of them
}