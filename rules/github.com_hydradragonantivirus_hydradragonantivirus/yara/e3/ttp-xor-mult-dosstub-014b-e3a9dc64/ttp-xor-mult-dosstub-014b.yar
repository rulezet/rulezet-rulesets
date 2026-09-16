rule TTP_XOR_MULT_DOSStub_014b {
  strings:
    $key_014b = { 55 23 [2] 21 3b [2] 66 39 [2] 21 28 [2] 6f 24 [2] 63 2e [2] 74 25 [2] 6f 6b [2] 52 }

  condition:
    any of them
}