rule TTP_XOR_MULT_DOSStub_8433 {
  strings:
    $key_8433 = { d0 5b [2] a4 43 [2] e3 41 [2] a4 50 [2] ea 5c [2] e6 56 [2] f1 5d [2] ea 13 [2] d7 }

  condition:
    any of them
}