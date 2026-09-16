rule TTP_XOR_MULT_DOSStub_8113 {
  strings:
    $key_8113 = { d5 7b [2] a1 63 [2] e6 61 [2] a1 70 [2] ef 7c [2] e3 76 [2] f4 7d [2] ef 33 [2] d2 }

  condition:
    any of them
}