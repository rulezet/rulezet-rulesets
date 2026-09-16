rule TTP_XOR_MULT_DOSStub_923e {
  strings:
    $key_923e = { c6 56 [2] b2 4e [2] f5 4c [2] b2 5d [2] fc 51 [2] f0 5b [2] e7 50 [2] fc 1e [2] c1 }

  condition:
    any of them
}