rule TTP_XOR_MULT_DOSStub_817e {
  strings:
    $key_817e = { d5 16 [2] a1 0e [2] e6 0c [2] a1 1d [2] ef 11 [2] e3 1b [2] f4 10 [2] ef 5e [2] d2 }

  condition:
    any of them
}