rule TTP_XOR_MULT_DOSStub_752b {
  strings:
    $key_752b = { 21 43 [2] 55 5b [2] 12 59 [2] 55 48 [2] 1b 44 [2] 17 4e [2] 00 45 [2] 1b 0b [2] 26 }

  condition:
    any of them
}