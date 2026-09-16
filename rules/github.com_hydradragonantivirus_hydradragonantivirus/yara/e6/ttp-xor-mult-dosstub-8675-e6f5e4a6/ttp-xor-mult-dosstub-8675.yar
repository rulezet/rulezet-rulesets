rule TTP_XOR_MULT_DOSStub_8675 {
  strings:
    $key_8675 = { d2 1d [2] a6 05 [2] e1 07 [2] a6 16 [2] e8 1a [2] e4 10 [2] f3 1b [2] e8 55 [2] d5 }

  condition:
    any of them
}