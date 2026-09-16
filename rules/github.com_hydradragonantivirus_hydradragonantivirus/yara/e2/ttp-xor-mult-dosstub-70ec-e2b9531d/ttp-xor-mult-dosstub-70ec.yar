rule TTP_XOR_MULT_DOSStub_70ec {
  strings:
    $key_70ec = { 24 84 [2] 50 9c [2] 17 9e [2] 50 8f [2] 1e 83 [2] 12 89 [2] 05 82 [2] 1e cc [2] 23 }

  condition:
    any of them
}