rule TTP_XOR_MULT_DOSStub_73ec {
  strings:
    $key_73ec = { 27 84 [2] 53 9c [2] 14 9e [2] 53 8f [2] 1d 83 [2] 11 89 [2] 06 82 [2] 1d cc [2] 20 }

  condition:
    any of them
}