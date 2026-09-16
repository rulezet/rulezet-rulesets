rule TTP_XOR_MULT_DOSStub_905b {
  strings:
    $key_905b = { c4 33 [2] b0 2b [2] f7 29 [2] b0 38 [2] fe 34 [2] f2 3e [2] e5 35 [2] fe 7b [2] c3 }

  condition:
    any of them
}