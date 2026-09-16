rule TTP_XOR_MULT_DOSStub_8340 {
  strings:
    $key_8340 = { d7 28 [2] a3 30 [2] e4 32 [2] a3 23 [2] ed 2f [2] e1 25 [2] f6 2e [2] ed 60 [2] d0 }

  condition:
    any of them
}