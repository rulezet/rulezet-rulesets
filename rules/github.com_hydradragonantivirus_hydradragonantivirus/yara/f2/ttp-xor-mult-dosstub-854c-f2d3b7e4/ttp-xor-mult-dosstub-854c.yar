rule TTP_XOR_MULT_DOSStub_854c {
  strings:
    $key_854c = { d1 24 [2] a5 3c [2] e2 3e [2] a5 2f [2] eb 23 [2] e7 29 [2] f0 22 [2] eb 6c [2] d6 }

  condition:
    any of them
}