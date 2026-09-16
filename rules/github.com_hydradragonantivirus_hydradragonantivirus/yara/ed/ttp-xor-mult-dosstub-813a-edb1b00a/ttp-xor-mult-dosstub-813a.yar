rule TTP_XOR_MULT_DOSStub_813a {
  strings:
    $key_813a = { d5 52 [2] a1 4a [2] e6 48 [2] a1 59 [2] ef 55 [2] e3 5f [2] f4 54 [2] ef 1a [2] d2 }

  condition:
    any of them
}