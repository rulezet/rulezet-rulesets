rule TTP_XOR_MULT_DOSStub_763b {
  strings:
    $key_763b = { 22 53 [2] 56 4b [2] 11 49 [2] 56 58 [2] 18 54 [2] 14 5e [2] 03 55 [2] 18 1b [2] 25 }

  condition:
    any of them
}