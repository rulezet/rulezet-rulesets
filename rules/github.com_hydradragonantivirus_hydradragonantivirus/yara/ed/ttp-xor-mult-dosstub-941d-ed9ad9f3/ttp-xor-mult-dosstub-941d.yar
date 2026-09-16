rule TTP_XOR_MULT_DOSStub_941d {
  strings:
    $key_941d = { c0 75 [2] b4 6d [2] f3 6f [2] b4 7e [2] fa 72 [2] f6 78 [2] e1 73 [2] fa 3d [2] c7 }

  condition:
    any of them
}