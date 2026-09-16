rule TTP_XOR_MULT_DOSStub_934d {
  strings:
    $key_934d = { c7 25 [2] b3 3d [2] f4 3f [2] b3 2e [2] fd 22 [2] f1 28 [2] e6 23 [2] fd 6d [2] c0 }

  condition:
    any of them
}