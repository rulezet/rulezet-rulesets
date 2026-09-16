rule TTP_XOR_MULT_DOSStub_52ec {
  strings:
    $key_52ec = { 06 84 [2] 72 9c [2] 35 9e [2] 72 8f [2] 3c 83 [2] 30 89 [2] 27 82 [2] 3c cc [2] 01 }

  condition:
    any of them
}