rule TTP_XOR_MULT_DOSStub_857b {
  strings:
    $key_857b = { d1 13 [2] a5 0b [2] e2 09 [2] a5 18 [2] eb 14 [2] e7 1e [2] f0 15 [2] eb 5b [2] d6 }

  condition:
    any of them
}