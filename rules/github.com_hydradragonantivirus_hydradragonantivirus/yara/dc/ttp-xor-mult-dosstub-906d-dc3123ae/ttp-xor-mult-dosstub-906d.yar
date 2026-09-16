rule TTP_XOR_MULT_DOSStub_906d {
  strings:
    $key_906d = { c4 05 [2] b0 1d [2] f7 1f [2] b0 0e [2] fe 02 [2] f2 08 [2] e5 03 [2] fe 4d [2] c3 }

  condition:
    any of them
}