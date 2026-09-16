rule TTP_XOR_MULT_DOSStub_94f2 {
  strings:
    $key_94f2 = { c0 9a [2] b4 82 [2] f3 80 [2] b4 91 [2] fa 9d [2] f6 97 [2] e1 9c [2] fa d2 [2] c7 }

  condition:
    any of them
}