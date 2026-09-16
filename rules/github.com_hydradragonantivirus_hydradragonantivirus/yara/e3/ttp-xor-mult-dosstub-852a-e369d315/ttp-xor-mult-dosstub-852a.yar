rule TTP_XOR_MULT_DOSStub_852a {
  strings:
    $key_852a = { d1 42 [2] a5 5a [2] e2 58 [2] a5 49 [2] eb 45 [2] e7 4f [2] f0 44 [2] eb 0a [2] d6 }

  condition:
    any of them
}