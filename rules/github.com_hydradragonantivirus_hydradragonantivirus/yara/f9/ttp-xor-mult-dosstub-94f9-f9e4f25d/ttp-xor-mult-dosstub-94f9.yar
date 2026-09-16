rule TTP_XOR_MULT_DOSStub_94f9 {
  strings:
    $key_94f9 = { c0 91 [2] b4 89 [2] f3 8b [2] b4 9a [2] fa 96 [2] f6 9c [2] e1 97 [2] fa d9 [2] c7 }

  condition:
    any of them
}