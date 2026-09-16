rule TTP_XOR_MULT_DOSStub_960a {
  strings:
    $key_960a = { c2 62 [2] b6 7a [2] f1 78 [2] b6 69 [2] f8 65 [2] f4 6f [2] e3 64 [2] f8 2a [2] c5 }

  condition:
    any of them
}