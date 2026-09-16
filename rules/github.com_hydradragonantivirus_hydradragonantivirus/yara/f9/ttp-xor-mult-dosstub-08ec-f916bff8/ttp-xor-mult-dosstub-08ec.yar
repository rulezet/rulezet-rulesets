rule TTP_XOR_MULT_DOSStub_08ec {
  strings:
    $key_08ec = { 5c 84 [2] 28 9c [2] 6f 9e [2] 28 8f [2] 66 83 [2] 6a 89 [2] 7d 82 [2] 66 cc [2] 5b }

  condition:
    any of them
}