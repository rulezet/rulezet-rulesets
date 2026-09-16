rule TTP_XOR_MULT_DOSStub_863e {
  strings:
    $key_863e = { d2 56 [2] a6 4e [2] e1 4c [2] a6 5d [2] e8 51 [2] e4 5b [2] f3 50 [2] e8 1e [2] d5 }

  condition:
    any of them
}