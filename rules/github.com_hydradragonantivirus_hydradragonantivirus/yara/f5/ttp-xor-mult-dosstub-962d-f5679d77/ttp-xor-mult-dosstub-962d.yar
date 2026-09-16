rule TTP_XOR_MULT_DOSStub_962d {
  strings:
    $key_962d = { c2 45 [2] b6 5d [2] f1 5f [2] b6 4e [2] f8 42 [2] f4 48 [2] e3 43 [2] f8 0d [2] c5 }

  condition:
    any of them
}