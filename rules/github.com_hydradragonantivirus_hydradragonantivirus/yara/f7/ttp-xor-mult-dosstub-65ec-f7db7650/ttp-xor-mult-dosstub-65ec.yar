rule TTP_XOR_MULT_DOSStub_65ec {
  strings:
    $key_65ec = { 31 84 [2] 45 9c [2] 02 9e [2] 45 8f [2] 0b 83 [2] 07 89 [2] 10 82 [2] 0b cc [2] 36 }

  condition:
    any of them
}