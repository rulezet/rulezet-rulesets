rule TTP_XOR_MULT_DOSStub_742b {
  strings:
    $key_742b = { 20 43 [2] 54 5b [2] 13 59 [2] 54 48 [2] 1a 44 [2] 16 4e [2] 01 45 [2] 1a 0b [2] 27 }

  condition:
    any of them
}