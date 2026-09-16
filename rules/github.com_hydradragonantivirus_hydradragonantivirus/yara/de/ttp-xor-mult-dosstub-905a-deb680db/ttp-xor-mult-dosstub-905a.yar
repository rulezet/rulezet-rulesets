rule TTP_XOR_MULT_DOSStub_905a {
  strings:
    $key_905a = { c4 32 [2] b0 2a [2] f7 28 [2] b0 39 [2] fe 35 [2] f2 3f [2] e5 34 [2] fe 7a [2] c3 }

  condition:
    any of them
}