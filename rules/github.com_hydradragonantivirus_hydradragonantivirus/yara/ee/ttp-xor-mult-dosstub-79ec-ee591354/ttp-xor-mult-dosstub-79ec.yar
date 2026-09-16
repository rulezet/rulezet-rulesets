rule TTP_XOR_MULT_DOSStub_79ec {
  strings:
    $key_79ec = { 2d 84 [2] 59 9c [2] 1e 9e [2] 59 8f [2] 17 83 [2] 1b 89 [2] 0c 82 [2] 17 cc [2] 2a }

  condition:
    any of them
}