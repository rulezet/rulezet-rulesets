rule TTP_XOR_MULT_DOSStub_8173 {
  strings:
    $key_8173 = { d5 1b [2] a1 03 [2] e6 01 [2] a1 10 [2] ef 1c [2] e3 16 [2] f4 1d [2] ef 53 [2] d2 }

  condition:
    any of them
}