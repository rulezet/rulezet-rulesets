rule TTP_XOR_MULT_DOSStub_902d {
  strings:
    $key_902d = { c4 45 [2] b0 5d [2] f7 5f [2] b0 4e [2] fe 42 [2] f2 48 [2] e5 43 [2] fe 0d [2] c3 }

  condition:
    any of them
}