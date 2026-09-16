rule TTP_XOR_MULT_DOSStub_fbac {
  strings:
    $key_fbac = { af c4 [2] db dc [2] 9c de [2] db cf [2] 95 c3 [2] 99 c9 [2] 8e c2 [2] 95 8c [2] a8 }

  condition:
    any of them
}