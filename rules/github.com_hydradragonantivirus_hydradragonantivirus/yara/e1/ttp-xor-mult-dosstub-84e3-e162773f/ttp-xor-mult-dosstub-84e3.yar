rule TTP_XOR_MULT_DOSStub_84e3 {
  strings:
    $key_84e3 = { d0 8b [2] a4 93 [2] e3 91 [2] a4 80 [2] ea 8c [2] e6 86 [2] f1 8d [2] ea c3 [2] d7 }

  condition:
    any of them
}