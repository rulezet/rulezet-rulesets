rule TTP_XOR_MULT_DOSStub_9621 {
  strings:
    $key_9621 = { c2 49 [2] b6 51 [2] f1 53 [2] b6 42 [2] f8 4e [2] f4 44 [2] e3 4f [2] f8 01 [2] c5 }

  condition:
    any of them
}