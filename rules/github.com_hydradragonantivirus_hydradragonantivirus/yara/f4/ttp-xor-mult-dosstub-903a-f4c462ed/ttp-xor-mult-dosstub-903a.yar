rule TTP_XOR_MULT_DOSStub_903a {
  strings:
    $key_903a = { c4 52 [2] b0 4a [2] f7 48 [2] b0 59 [2] fe 55 [2] f2 5f [2] e5 54 [2] fe 1a [2] c3 }

  condition:
    any of them
}