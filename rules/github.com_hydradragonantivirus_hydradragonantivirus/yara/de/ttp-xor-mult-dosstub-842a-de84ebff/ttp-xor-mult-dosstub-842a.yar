rule TTP_XOR_MULT_DOSStub_842a {
  strings:
    $key_842a = { d0 42 [2] a4 5a [2] e3 58 [2] a4 49 [2] ea 45 [2] e6 4f [2] f1 44 [2] ea 0a [2] d7 }

  condition:
    any of them
}