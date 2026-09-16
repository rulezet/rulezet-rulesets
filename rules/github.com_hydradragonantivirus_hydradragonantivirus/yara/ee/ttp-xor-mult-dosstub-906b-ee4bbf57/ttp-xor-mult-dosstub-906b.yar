rule TTP_XOR_MULT_DOSStub_906b {
  strings:
    $key_906b = { c4 03 [2] b0 1b [2] f7 19 [2] b0 08 [2] fe 04 [2] f2 0e [2] e5 05 [2] fe 4b [2] c3 }

  condition:
    any of them
}