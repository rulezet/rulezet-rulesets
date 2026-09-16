rule TTP_XOR_MULT_DOSStub_9727 {
  strings:
    $key_9727 = { c3 4f [2] b7 57 [2] f0 55 [2] b7 44 [2] f9 48 [2] f5 42 [2] e2 49 [2] f9 07 [2] c4 }

  condition:
    any of them
}