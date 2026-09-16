rule TTP_XOR_MULT_DOSStub_8ed7 {
  strings:
    $key_8ed7 = { da bf [2] ae a7 [2] e9 a5 [2] ae b4 [2] e0 b8 [2] ec b2 [2] fb b9 [2] e0 f7 [2] dd }

  condition:
    any of them
}