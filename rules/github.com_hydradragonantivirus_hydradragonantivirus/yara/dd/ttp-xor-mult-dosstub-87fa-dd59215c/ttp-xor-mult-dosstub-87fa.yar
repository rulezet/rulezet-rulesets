rule TTP_XOR_MULT_DOSStub_87fa {
  strings:
    $key_87fa = { d3 92 [2] a7 8a [2] e0 88 [2] a7 99 [2] e9 95 [2] e5 9f [2] f2 94 [2] e9 da [2] d4 }

  condition:
    any of them
}