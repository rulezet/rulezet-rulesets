rule TTP_XOR_MULT_DOSStub_964d {
  strings:
    $key_964d = { c2 25 [2] b6 3d [2] f1 3f [2] b6 2e [2] f8 22 [2] f4 28 [2] e3 23 [2] f8 6d [2] c5 }

  condition:
    any of them
}