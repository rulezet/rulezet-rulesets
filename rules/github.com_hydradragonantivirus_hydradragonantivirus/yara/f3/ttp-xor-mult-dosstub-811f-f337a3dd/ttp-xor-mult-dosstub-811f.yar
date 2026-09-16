rule TTP_XOR_MULT_DOSStub_811f {
  strings:
    $key_811f = { d5 77 [2] a1 6f [2] e6 6d [2] a1 7c [2] ef 70 [2] e3 7a [2] f4 71 [2] ef 3f [2] d2 }

  condition:
    any of them
}