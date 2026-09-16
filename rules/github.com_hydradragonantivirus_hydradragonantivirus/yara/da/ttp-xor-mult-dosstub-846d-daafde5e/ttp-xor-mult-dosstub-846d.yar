rule TTP_XOR_MULT_DOSStub_846d {
  strings:
    $key_846d = { d0 05 [2] a4 1d [2] e3 1f [2] a4 0e [2] ea 02 [2] e6 08 [2] f1 03 [2] ea 4d [2] d7 }

  condition:
    any of them
}