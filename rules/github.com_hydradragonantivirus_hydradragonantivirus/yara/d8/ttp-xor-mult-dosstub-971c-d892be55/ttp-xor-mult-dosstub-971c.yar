rule TTP_XOR_MULT_DOSStub_971c {
  strings:
    $key_971c = { c3 74 [2] b7 6c [2] f0 6e [2] b7 7f [2] f9 73 [2] f5 79 [2] e2 72 [2] f9 3c [2] c4 }

  condition:
    any of them
}