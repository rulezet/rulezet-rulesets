rule TTP_XOR_MULT_DOSStub_59ec {
  strings:
    $key_59ec = { 0d 84 [2] 79 9c [2] 3e 9e [2] 79 8f [2] 37 83 [2] 3b 89 [2] 2c 82 [2] 37 cc [2] 0a }

  condition:
    any of them
}