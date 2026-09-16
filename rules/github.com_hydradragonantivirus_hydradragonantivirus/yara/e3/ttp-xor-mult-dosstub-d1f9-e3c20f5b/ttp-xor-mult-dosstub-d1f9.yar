rule TTP_XOR_MULT_DOSStub_d1f9 {
  strings:
    $key_d1f9 = { 85 91 [2] f1 89 [2] b6 8b [2] f1 9a [2] bf 96 [2] b3 9c [2] a4 97 [2] bf d9 [2] 82 }

  condition:
    any of them
}