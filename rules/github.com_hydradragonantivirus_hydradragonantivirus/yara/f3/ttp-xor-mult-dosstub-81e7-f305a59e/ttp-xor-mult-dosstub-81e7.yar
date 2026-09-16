rule TTP_XOR_MULT_DOSStub_81e7 {
  strings:
    $key_81e7 = { d5 8f [2] a1 97 [2] e6 95 [2] a1 84 [2] ef 88 [2] e3 82 [2] f4 89 [2] ef c7 [2] d2 }

  condition:
    any of them
}