rule TTP_XOR_MULT_DOSStub_964e {
  strings:
    $key_964e = { c2 26 [2] b6 3e [2] f1 3c [2] b6 2d [2] f8 21 [2] f4 2b [2] e3 20 [2] f8 6e [2] c5 }

  condition:
    any of them
}