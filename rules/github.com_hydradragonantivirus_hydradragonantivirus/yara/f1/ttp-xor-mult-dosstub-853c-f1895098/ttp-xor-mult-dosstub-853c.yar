rule TTP_XOR_MULT_DOSStub_853c {
  strings:
    $key_853c = { d1 54 [2] a5 4c [2] e2 4e [2] a5 5f [2] eb 53 [2] e7 59 [2] f0 52 [2] eb 1c [2] d6 }

  condition:
    any of them
}