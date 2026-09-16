rule TTP_XOR_MULT_DOSStub_463b {
  strings:
    $key_463b = { 12 53 [2] 66 4b [2] 21 49 [2] 66 58 [2] 28 54 [2] 24 5e [2] 33 55 [2] 28 1b [2] 15 }

  condition:
    any of them
}