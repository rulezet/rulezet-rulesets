rule TTP_XOR_MULT_DOSStub_911a {
  strings:
    $key_911a = { c5 72 [2] b1 6a [2] f6 68 [2] b1 79 [2] ff 75 [2] f3 7f [2] e4 74 [2] ff 3a [2] c2 }

  condition:
    any of them
}