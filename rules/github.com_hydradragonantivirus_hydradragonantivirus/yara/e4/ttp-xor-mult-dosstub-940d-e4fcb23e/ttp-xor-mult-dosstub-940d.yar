rule TTP_XOR_MULT_DOSStub_940d {
  strings:
    $key_940d = { c0 65 [2] b4 7d [2] f3 7f [2] b4 6e [2] fa 62 [2] f6 68 [2] e1 63 [2] fa 2d [2] c7 }

  condition:
    any of them
}