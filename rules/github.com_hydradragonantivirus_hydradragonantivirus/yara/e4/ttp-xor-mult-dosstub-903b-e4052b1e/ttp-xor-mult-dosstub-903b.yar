rule TTP_XOR_MULT_DOSStub_903b {
  strings:
    $key_903b = { c4 53 [2] b0 4b [2] f7 49 [2] b0 58 [2] fe 54 [2] f2 5e [2] e5 55 [2] fe 1b [2] c3 }

  condition:
    any of them
}