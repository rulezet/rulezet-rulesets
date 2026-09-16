rule TTP_XOR_MULT_DOSStub_89a0 {
  strings:
    $key_89a0 = { dd c8 [2] a9 d0 [2] ee d2 [2] a9 c3 [2] e7 cf [2] eb c5 [2] fc ce [2] e7 80 [2] da }

  condition:
    any of them
}