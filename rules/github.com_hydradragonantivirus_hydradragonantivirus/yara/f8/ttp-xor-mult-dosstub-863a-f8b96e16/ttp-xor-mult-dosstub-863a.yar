rule TTP_XOR_MULT_DOSStub_863a {
  strings:
    $key_863a = { d2 52 [2] a6 4a [2] e1 48 [2] a6 59 [2] e8 55 [2] e4 5f [2] f3 54 [2] e8 1a [2] d5 }

  condition:
    any of them
}