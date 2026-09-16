rule TTP_XOR_MULT_DOSStub_84f4 {
  strings:
    $key_84f4 = { d0 9c [2] a4 84 [2] e3 86 [2] a4 97 [2] ea 9b [2] e6 91 [2] f1 9a [2] ea d4 [2] d7 }

  condition:
    any of them
}