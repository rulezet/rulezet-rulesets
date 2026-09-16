rule TTP_XOR_MULT_DOSStub_9415 {
  strings:
    $key_9415 = { c0 7d [2] b4 65 [2] f3 67 [2] b4 76 [2] fa 7a [2] f6 70 [2] e1 7b [2] fa 35 [2] c7 }

  condition:
    any of them
}