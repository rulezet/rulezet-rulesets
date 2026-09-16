rule TTP_XOR_MULT_DOSStub_84f0 {
  strings:
    $key_84f0 = { d0 98 [2] a4 80 [2] e3 82 [2] a4 93 [2] ea 9f [2] e6 95 [2] f1 9e [2] ea d0 [2] d7 }

  condition:
    any of them
}