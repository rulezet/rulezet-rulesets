rule TTP_XOR_MULT_DOSStub_901d {
  strings:
    $key_901d = { c4 75 [2] b0 6d [2] f7 6f [2] b0 7e [2] fe 72 [2] f2 78 [2] e5 73 [2] fe 3d [2] c3 }

  condition:
    any of them
}