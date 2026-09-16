rule TTP_XOR_MULT_DOSStub_95f3 {
  strings:
    $key_95f3 = { c1 9b [2] b5 83 [2] f2 81 [2] b5 90 [2] fb 9c [2] f7 96 [2] e0 9d [2] fb d3 [2] c6 }

  condition:
    any of them
}