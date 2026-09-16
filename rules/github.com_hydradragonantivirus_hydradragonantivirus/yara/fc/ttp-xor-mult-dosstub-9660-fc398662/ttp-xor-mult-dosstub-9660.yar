rule TTP_XOR_MULT_DOSStub_9660 {
  strings:
    $key_9660 = { c2 08 [2] b6 10 [2] f1 12 [2] b6 03 [2] f8 0f [2] f4 05 [2] e3 0e [2] f8 40 [2] c5 }

  condition:
    any of them
}