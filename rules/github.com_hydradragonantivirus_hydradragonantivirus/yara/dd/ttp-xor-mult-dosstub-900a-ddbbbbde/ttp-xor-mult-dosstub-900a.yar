rule TTP_XOR_MULT_DOSStub_900a {
  strings:
    $key_900a = { c4 62 [2] b0 7a [2] f7 78 [2] b0 69 [2] fe 65 [2] f2 6f [2] e5 64 [2] fe 2a [2] c3 }

  condition:
    any of them
}