rule TTP_XOR_MULT_DOSStub_22ec {
  strings:
    $key_22ec = { 76 84 [2] 02 9c [2] 45 9e [2] 02 8f [2] 4c 83 [2] 40 89 [2] 57 82 [2] 4c cc [2] 71 }

  condition:
    any of them
}