rule TTP_XOR_MULT_DOSStub_8431 {
  strings:
    $key_8431 = { d0 59 [2] a4 41 [2] e3 43 [2] a4 52 [2] ea 5e [2] e6 54 [2] f1 5f [2] ea 11 [2] d7 }

  condition:
    any of them
}