rule TTP_XOR_MULT_DOSStub_47ec {
  strings:
    $key_47ec = { 13 84 [2] 67 9c [2] 20 9e [2] 67 8f [2] 29 83 [2] 25 89 [2] 32 82 [2] 29 cc [2] 14 }

  condition:
    any of them
}