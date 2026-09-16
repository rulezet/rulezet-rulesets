rule TTP_XOR_MULT_DOSStub_840e {
  strings:
    $key_840e = { d0 66 [2] a4 7e [2] e3 7c [2] a4 6d [2] ea 61 [2] e6 6b [2] f1 60 [2] ea 2e [2] d7 }

  condition:
    any of them
}