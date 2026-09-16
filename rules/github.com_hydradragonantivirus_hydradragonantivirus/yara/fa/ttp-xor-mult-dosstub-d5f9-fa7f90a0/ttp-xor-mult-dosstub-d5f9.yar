rule TTP_XOR_MULT_DOSStub_d5f9 {
  strings:
    $key_d5f9 = { 81 91 [2] f5 89 [2] b2 8b [2] f5 9a [2] bb 96 [2] b7 9c [2] a0 97 [2] bb d9 [2] 86 }

  condition:
    any of them
}