rule TTP_XOR_MULT_DOSStub_97ec {
  strings:
    $key_97ec = { c3 84 [2] b7 9c [2] f0 9e [2] b7 8f [2] f9 83 [2] f5 89 [2] e2 82 [2] f9 cc [2] c4 }

  condition:
    any of them
}