rule TTP_XOR_MULT_DOSStub_971d {
  strings:
    $key_971d = { c3 75 [2] b7 6d [2] f0 6f [2] b7 7e [2] f9 72 [2] f5 78 [2] e2 73 [2] f9 3d [2] c4 }

  condition:
    any of them
}