rule TTP_XOR_MULT_DOSStub_963b {
  strings:
    $key_963b = { c2 53 [2] b6 4b [2] f1 49 [2] b6 58 [2] f8 54 [2] f4 5e [2] e3 55 [2] f8 1b [2] c5 }

  condition:
    any of them
}