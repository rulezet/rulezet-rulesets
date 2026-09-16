rule TTP_XOR_MULT_DOSStub_841f {
  strings:
    $key_841f = { d0 77 [2] a4 6f [2] e3 6d [2] a4 7c [2] ea 70 [2] e6 7a [2] f1 71 [2] ea 3f [2] d7 }

  condition:
    any of them
}