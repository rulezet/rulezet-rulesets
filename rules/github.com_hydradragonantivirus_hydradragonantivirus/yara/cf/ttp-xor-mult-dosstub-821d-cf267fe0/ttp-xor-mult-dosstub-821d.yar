rule TTP_XOR_MULT_DOSStub_821d {
  strings:
    $key_821d = { d6 75 [2] a2 6d [2] e5 6f [2] a2 7e [2] ec 72 [2] e0 78 [2] f7 73 [2] ec 3d [2] d1 }

  condition:
    any of them
}