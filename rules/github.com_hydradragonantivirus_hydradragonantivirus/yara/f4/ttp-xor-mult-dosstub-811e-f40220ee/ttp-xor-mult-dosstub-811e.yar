rule TTP_XOR_MULT_DOSStub_811e {
  strings:
    $key_811e = { d5 76 [2] a1 6e [2] e6 6c [2] a1 7d [2] ef 71 [2] e3 7b [2] f4 70 [2] ef 3e [2] d2 }

  condition:
    any of them
}