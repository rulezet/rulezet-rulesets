rule TTP_XOR_MULT_DOSStub_8435 {
  strings:
    $key_8435 = { d0 5d [2] a4 45 [2] e3 47 [2] a4 56 [2] ea 5a [2] e6 50 [2] f1 5b [2] ea 15 [2] d7 }

  condition:
    any of them
}