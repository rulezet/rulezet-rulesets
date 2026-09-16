rule TTP_XOR_MULT_DOSStub_a7ec {
  strings:
    $key_a7ec = { f3 84 [2] 87 9c [2] c0 9e [2] 87 8f [2] c9 83 [2] c5 89 [2] d2 82 [2] c9 cc [2] f4 }

  condition:
    any of them
}