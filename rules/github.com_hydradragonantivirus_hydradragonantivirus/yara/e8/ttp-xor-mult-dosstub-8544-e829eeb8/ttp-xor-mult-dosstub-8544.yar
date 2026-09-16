rule TTP_XOR_MULT_DOSStub_8544 {
  strings:
    $key_8544 = { d1 2c [2] a5 34 [2] e2 36 [2] a5 27 [2] eb 2b [2] e7 21 [2] f0 2a [2] eb 64 [2] d6 }

  condition:
    any of them
}