rule TTP_XOR_MULT_DOSStub_472b {
  strings:
    $key_472b = { 13 43 [2] 67 5b [2] 20 59 [2] 67 48 [2] 29 44 [2] 25 4e [2] 32 45 [2] 29 0b [2] 14 }

  condition:
    any of them
}