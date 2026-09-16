rule TTP_XOR_MULT_DOSStub_9707 {
  strings:
    $key_9707 = { c3 6f [2] b7 77 [2] f0 75 [2] b7 64 [2] f9 68 [2] f5 62 [2] e2 69 [2] f9 27 [2] c4 }

  condition:
    any of them
}