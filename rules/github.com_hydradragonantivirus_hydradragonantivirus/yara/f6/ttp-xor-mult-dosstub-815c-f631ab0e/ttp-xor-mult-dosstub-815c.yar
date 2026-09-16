rule TTP_XOR_MULT_DOSStub_815c {
  strings:
    $key_815c = { d5 34 [2] a1 2c [2] e6 2e [2] a1 3f [2] ef 33 [2] e3 39 [2] f4 32 [2] ef 7c [2] d2 }

  condition:
    any of them
}