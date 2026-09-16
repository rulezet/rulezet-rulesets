rule TTP_XOR_MULT_DOSStub_845e {
  strings:
    $key_845e = { d0 36 [2] a4 2e [2] e3 2c [2] a4 3d [2] ea 31 [2] e6 3b [2] f1 30 [2] ea 7e [2] d7 }

  condition:
    any of them
}