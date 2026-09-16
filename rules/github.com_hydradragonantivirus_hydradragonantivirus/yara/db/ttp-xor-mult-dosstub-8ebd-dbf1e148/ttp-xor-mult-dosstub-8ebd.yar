rule TTP_XOR_MULT_DOSStub_8ebd {
  strings:
    $key_8ebd = { da d5 [2] ae cd [2] e9 cf [2] ae de [2] e0 d2 [2] ec d8 [2] fb d3 [2] e0 9d [2] dd }

  condition:
    any of them
}