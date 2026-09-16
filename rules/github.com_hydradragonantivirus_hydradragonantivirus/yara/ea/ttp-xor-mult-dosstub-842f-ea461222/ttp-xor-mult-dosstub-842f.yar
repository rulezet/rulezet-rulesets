rule TTP_XOR_MULT_DOSStub_842f {
  strings:
    $key_842f = { d0 47 [2] a4 5f [2] e3 5d [2] a4 4c [2] ea 40 [2] e6 4a [2] f1 41 [2] ea 0f [2] d7 }

  condition:
    any of them
}