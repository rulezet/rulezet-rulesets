rule TTP_XOR_MULT_DOSStub_8153 {
  strings:
    $key_8153 = { d5 3b [2] a1 23 [2] e6 21 [2] a1 30 [2] ef 3c [2] e3 36 [2] f4 3d [2] ef 73 [2] d2 }

  condition:
    any of them
}