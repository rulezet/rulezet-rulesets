rule TTP_XOR_MULT_DOSStub_846f {
  strings:
    $key_846f = { d0 07 [2] a4 1f [2] e3 1d [2] a4 0c [2] ea 00 [2] e6 0a [2] f1 01 [2] ea 4f [2] d7 }

  condition:
    any of them
}