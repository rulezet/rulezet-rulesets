rule TTP_XOR_MULT_DOSStub_827d {
  strings:
    $key_827d = { d6 15 [2] a2 0d [2] e5 0f [2] a2 1e [2] ec 12 [2] e0 18 [2] f7 13 [2] ec 5d [2] d1 }

  condition:
    any of them
}