rule TTP_XOR_MULT_DOSStub_92e5 {
  strings:
    $key_92e5 = { c6 8d [2] b2 95 [2] f5 97 [2] b2 86 [2] fc 8a [2] f0 80 [2] e7 8b [2] fc c5 [2] c1 }

  condition:
    any of them
}