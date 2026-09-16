rule TTP_XOR_MULT_DOSStub_81e8 {
  strings:
    $key_81e8 = { d5 80 [2] a1 98 [2] e6 9a [2] a1 8b [2] ef 87 [2] e3 8d [2] f4 86 [2] ef c8 [2] d2 }

  condition:
    any of them
}