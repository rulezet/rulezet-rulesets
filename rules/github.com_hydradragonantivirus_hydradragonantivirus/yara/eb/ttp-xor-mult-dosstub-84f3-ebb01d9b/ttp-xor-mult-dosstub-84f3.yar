rule TTP_XOR_MULT_DOSStub_84f3 {
  strings:
    $key_84f3 = { d0 9b [2] a4 83 [2] e3 81 [2] a4 90 [2] ea 9c [2] e6 96 [2] f1 9d [2] ea d3 [2] d7 }

  condition:
    any of them
}