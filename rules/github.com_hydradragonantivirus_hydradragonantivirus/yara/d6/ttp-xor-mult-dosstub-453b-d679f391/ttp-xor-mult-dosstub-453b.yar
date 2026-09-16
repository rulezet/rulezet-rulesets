rule TTP_XOR_MULT_DOSStub_453b {
  strings:
    $key_453b = { 11 53 [2] 65 4b [2] 22 49 [2] 65 58 [2] 2b 54 [2] 27 5e [2] 30 55 [2] 2b 1b [2] 16 }

  condition:
    any of them
}