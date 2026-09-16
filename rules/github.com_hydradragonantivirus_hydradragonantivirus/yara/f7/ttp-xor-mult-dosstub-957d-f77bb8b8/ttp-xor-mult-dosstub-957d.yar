rule TTP_XOR_MULT_DOSStub_957d {
  strings:
    $key_957d = { c1 15 [2] b5 0d [2] f2 0f [2] b5 1e [2] fb 12 [2] f7 18 [2] e0 13 [2] fb 5d [2] c6 }

  condition:
    any of them
}