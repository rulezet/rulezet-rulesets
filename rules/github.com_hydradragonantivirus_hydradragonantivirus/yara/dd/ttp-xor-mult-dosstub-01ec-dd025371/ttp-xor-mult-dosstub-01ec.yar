rule TTP_XOR_MULT_DOSStub_01ec {
  strings:
    $key_01ec = { 55 84 [2] 21 9c [2] 66 9e [2] 21 8f [2] 6f 83 [2] 63 89 [2] 74 82 [2] 6f cc [2] 52 }

  condition:
    any of them
}