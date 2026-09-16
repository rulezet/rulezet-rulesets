rule TTP_XOR_MULT_DOSStub_84fa {
  strings:
    $key_84fa = { d0 92 [2] a4 8a [2] e3 88 [2] a4 99 [2] ea 95 [2] e6 9f [2] f1 94 [2] ea da [2] d7 }

  condition:
    any of them
}