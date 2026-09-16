rule TTP_XOR_MULT_DOSStub_8574 {
  strings:
    $key_8574 = { d1 1c [2] a5 04 [2] e2 06 [2] a5 17 [2] eb 1b [2] e7 11 [2] f0 1a [2] eb 54 [2] d6 }

  condition:
    any of them
}