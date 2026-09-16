rule TTP_XOR_MULT_DOSStub_840d {
  strings:
    $key_840d = { d0 65 [2] a4 7d [2] e3 7f [2] a4 6e [2] ea 62 [2] e6 68 [2] f1 63 [2] ea 2d [2] d7 }

  condition:
    any of them
}