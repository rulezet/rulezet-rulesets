rule TTP_XOR_MULT_DOSStub_974c {
  strings:
    $key_974c = { c3 24 [2] b7 3c [2] f0 3e [2] b7 2f [2] f9 23 [2] f5 29 [2] e2 22 [2] f9 6c [2] c4 }

  condition:
    any of them
}