rule TTP_XOR_MULT_DOSStub_8bad {
  strings:
    $key_8bad = { df c5 [2] ab dd [2] ec df [2] ab ce [2] e5 c2 [2] e9 c8 [2] fe c3 [2] e5 8d [2] d8 }

  condition:
    any of them
}