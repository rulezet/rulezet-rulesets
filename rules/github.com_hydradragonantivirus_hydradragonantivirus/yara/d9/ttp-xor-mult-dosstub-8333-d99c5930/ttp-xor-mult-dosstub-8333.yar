rule TTP_XOR_MULT_DOSStub_8333 {
  strings:
    $key_8333 = { d7 5b [2] a3 43 [2] e4 41 [2] a3 50 [2] ed 5c [2] e1 56 [2] f6 5d [2] ed 13 [2] d0 }

  condition:
    any of them
}