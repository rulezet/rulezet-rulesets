rule TTP_XOR_MULT_DOSStub_81a3 {
  strings:
    $key_81a3 = { d5 cb [2] a1 d3 [2] e6 d1 [2] a1 c0 [2] ef cc [2] e3 c6 [2] f4 cd [2] ef 83 [2] d2 }

  condition:
    any of them
}