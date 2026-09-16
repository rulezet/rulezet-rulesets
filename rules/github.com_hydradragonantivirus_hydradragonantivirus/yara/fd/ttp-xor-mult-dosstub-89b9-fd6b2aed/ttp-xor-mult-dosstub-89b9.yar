rule TTP_XOR_MULT_DOSStub_89b9 {
  strings:
    $key_89b9 = { dd d1 [2] a9 c9 [2] ee cb [2] a9 da [2] e7 d6 [2] eb dc [2] fc d7 [2] e7 99 [2] da }

  condition:
    any of them
}