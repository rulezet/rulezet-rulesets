rule TTP_XOR_MULT_DOSStub_844e {
  strings:
    $key_844e = { d0 26 [2] a4 3e [2] e3 3c [2] a4 2d [2] ea 21 [2] e6 2b [2] f1 20 [2] ea 6e [2] d7 }

  condition:
    any of them
}