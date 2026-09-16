rule TTP_XOR_MULT_DOSStub_85e3 {
  strings:
    $key_85e3 = { d1 8b [2] a5 93 [2] e2 91 [2] a5 80 [2] eb 8c [2] e7 86 [2] f0 8d [2] eb c3 [2] d6 }

  condition:
    any of them
}