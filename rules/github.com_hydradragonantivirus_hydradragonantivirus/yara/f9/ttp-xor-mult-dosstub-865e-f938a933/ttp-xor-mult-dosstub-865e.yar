rule TTP_XOR_MULT_DOSStub_865e {
  strings:
    $key_865e = { d2 36 [2] a6 2e [2] e1 2c [2] a6 3d [2] e8 31 [2] e4 3b [2] f3 30 [2] e8 7e [2] d5 }

  condition:
    any of them
}