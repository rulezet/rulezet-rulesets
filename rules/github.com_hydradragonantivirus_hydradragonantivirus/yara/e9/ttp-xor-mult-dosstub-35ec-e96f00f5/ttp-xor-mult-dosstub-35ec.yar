rule TTP_XOR_MULT_DOSStub_35ec {
  strings:
    $key_35ec = { 61 84 [2] 15 9c [2] 52 9e [2] 15 8f [2] 5b 83 [2] 57 89 [2] 40 82 [2] 5b cc [2] 66 }

  condition:
    any of them
}