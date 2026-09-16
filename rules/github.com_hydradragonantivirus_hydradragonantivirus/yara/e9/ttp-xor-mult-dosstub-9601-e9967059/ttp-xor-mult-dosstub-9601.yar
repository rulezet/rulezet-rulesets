rule TTP_XOR_MULT_DOSStub_9601 {
  strings:
    $key_9601 = { c2 69 [2] b6 71 [2] f1 73 [2] b6 62 [2] f8 6e [2] f4 64 [2] e3 6f [2] f8 21 [2] c5 }

  condition:
    any of them
}