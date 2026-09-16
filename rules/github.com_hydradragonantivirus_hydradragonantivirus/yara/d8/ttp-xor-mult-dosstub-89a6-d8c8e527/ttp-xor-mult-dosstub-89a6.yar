rule TTP_XOR_MULT_DOSStub_89a6 {
  strings:
    $key_89a6 = { dd ce [2] a9 d6 [2] ee d4 [2] a9 c5 [2] e7 c9 [2] eb c3 [2] fc c8 [2] e7 86 [2] da }

  condition:
    any of them
}