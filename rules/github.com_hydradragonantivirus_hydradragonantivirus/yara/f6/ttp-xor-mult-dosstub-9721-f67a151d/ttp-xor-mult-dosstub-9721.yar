rule TTP_XOR_MULT_DOSStub_9721 {
  strings:
    $key_9721 = { c3 49 [2] b7 51 [2] f0 53 [2] b7 42 [2] f9 4e [2] f5 44 [2] e2 4f [2] f9 01 [2] c4 }

  condition:
    any of them
}