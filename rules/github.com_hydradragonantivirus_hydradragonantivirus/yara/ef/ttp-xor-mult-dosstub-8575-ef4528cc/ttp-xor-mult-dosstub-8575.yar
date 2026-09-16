rule TTP_XOR_MULT_DOSStub_8575 {
  strings:
    $key_8575 = { d1 1d [2] a5 05 [2] e2 07 [2] a5 16 [2] eb 1a [2] e7 10 [2] f0 1b [2] eb 55 [2] d6 }

  condition:
    any of them
}