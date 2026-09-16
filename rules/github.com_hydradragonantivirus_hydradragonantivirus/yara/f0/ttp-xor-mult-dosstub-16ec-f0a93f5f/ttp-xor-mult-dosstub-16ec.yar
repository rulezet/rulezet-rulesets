rule TTP_XOR_MULT_DOSStub_16ec {
  strings:
    $key_16ec = { 42 84 [2] 36 9c [2] 71 9e [2] 36 8f [2] 78 83 [2] 74 89 [2] 63 82 [2] 78 cc [2] 45 }

  condition:
    any of them
}