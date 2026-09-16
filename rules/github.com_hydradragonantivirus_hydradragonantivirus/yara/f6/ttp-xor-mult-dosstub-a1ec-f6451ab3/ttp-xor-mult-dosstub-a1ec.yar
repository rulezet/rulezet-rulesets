rule TTP_XOR_MULT_DOSStub_a1ec {
  strings:
    $key_a1ec = { f5 84 [2] 81 9c [2] c6 9e [2] 81 8f [2] cf 83 [2] c3 89 [2] d4 82 [2] cf cc [2] f2 }

  condition:
    any of them
}