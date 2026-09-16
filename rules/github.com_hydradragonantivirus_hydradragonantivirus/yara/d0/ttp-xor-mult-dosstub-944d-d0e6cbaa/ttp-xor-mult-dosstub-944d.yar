rule TTP_XOR_MULT_DOSStub_944d {
  strings:
    $key_944d = { c0 25 [2] b4 3d [2] f3 3f [2] b4 2e [2] fa 22 [2] f6 28 [2] e1 23 [2] fa 6d [2] c7 }

  condition:
    any of them
}