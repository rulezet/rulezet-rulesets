rule TTP_XOR_MULT_DOSStub_003b {
  strings:
    $key_003b = { 54 53 [2] 20 4b [2] 67 49 [2] 20 58 [2] 6e 54 [2] 62 5e [2] 75 55 [2] 6e 1b [2] 53 }

  condition:
    any of them
}