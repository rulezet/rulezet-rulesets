rule TTP_XOR_MULT_DOSStub_860d {
  strings:
    $key_860d = { d2 65 [2] a6 7d [2] e1 7f [2] a6 6e [2] e8 62 [2] e4 68 [2] f3 63 [2] e8 2d [2] d5 }

  condition:
    any of them
}