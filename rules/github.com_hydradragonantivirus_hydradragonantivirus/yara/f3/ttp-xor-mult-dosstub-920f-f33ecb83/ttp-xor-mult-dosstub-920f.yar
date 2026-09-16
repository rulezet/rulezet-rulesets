rule TTP_XOR_MULT_DOSStub_920f {
  strings:
    $key_920f = { c6 67 [2] b2 7f [2] f5 7d [2] b2 6c [2] fc 60 [2] f0 6a [2] e7 61 [2] fc 2f [2] c1 }

  condition:
    any of them
}