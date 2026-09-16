rule TTP_XOR_MULT_DOSStub_9726 {
  strings:
    $key_9726 = { c3 4e [2] b7 56 [2] f0 54 [2] b7 45 [2] f9 49 [2] f5 43 [2] e2 48 [2] f9 06 [2] c4 }

  condition:
    any of them
}