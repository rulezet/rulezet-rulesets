rule TTP_XOR_MULT_DOSStub_944a {
  strings:
    $key_944a = { c0 22 [2] b4 3a [2] f3 38 [2] b4 29 [2] fa 25 [2] f6 2f [2] e1 24 [2] fa 6a [2] c7 }

  condition:
    any of them
}