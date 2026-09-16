rule TTP_XOR_MULT_DOSStub_d8f9 {
  strings:
    $key_d8f9 = { 8c 91 [2] f8 89 [2] bf 8b [2] f8 9a [2] b6 96 [2] ba 9c [2] ad 97 [2] b6 d9 [2] 8b }

  condition:
    any of them
}