rule TTP_XOR_MULT_DOSStub_8ea1 {
  strings:
    $key_8ea1 = { da c9 [2] ae d1 [2] e9 d3 [2] ae c2 [2] e0 ce [2] ec c4 [2] fb cf [2] e0 81 [2] dd }

  condition:
    any of them
}