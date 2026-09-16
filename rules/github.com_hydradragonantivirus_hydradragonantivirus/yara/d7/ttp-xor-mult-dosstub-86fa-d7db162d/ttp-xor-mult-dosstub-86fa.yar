rule TTP_XOR_MULT_DOSStub_86fa {
  strings:
    $key_86fa = { d2 92 [2] a6 8a [2] e1 88 [2] a6 99 [2] e8 95 [2] e4 9f [2] f3 94 [2] e8 da [2] d5 }

  condition:
    any of them
}