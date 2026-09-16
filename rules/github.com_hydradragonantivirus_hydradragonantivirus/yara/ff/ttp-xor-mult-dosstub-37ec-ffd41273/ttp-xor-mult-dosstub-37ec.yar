rule TTP_XOR_MULT_DOSStub_37ec {
  strings:
    $key_37ec = { 63 84 [2] 17 9c [2] 50 9e [2] 17 8f [2] 59 83 [2] 55 89 [2] 42 82 [2] 59 cc [2] 64 }

  condition:
    any of them
}