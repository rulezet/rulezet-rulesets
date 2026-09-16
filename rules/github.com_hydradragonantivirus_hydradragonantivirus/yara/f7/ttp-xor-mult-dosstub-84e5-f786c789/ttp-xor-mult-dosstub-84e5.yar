rule TTP_XOR_MULT_DOSStub_84e5 {
  strings:
    $key_84e5 = { d0 8d [2] a4 95 [2] e3 97 [2] a4 86 [2] ea 8a [2] e6 80 [2] f1 8b [2] ea c5 [2] d7 }

  condition:
    any of them
}