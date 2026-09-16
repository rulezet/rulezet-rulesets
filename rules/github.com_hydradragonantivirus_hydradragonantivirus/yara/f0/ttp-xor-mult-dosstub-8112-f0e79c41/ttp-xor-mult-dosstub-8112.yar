rule TTP_XOR_MULT_DOSStub_8112 {
  strings:
    $key_8112 = { d5 7a [2] a1 62 [2] e6 60 [2] a1 71 [2] ef 7d [2] e3 77 [2] f4 7c [2] ef 32 [2] d2 }

  condition:
    any of them
}