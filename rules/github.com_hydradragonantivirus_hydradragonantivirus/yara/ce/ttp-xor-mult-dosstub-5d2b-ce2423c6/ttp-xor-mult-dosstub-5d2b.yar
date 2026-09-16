rule TTP_XOR_MULT_DOSStub_5d2b {
  strings:
    $key_5d2b = { 09 43 [2] 7d 5b [2] 3a 59 [2] 7d 48 [2] 33 44 [2] 3f 4e [2] 28 45 [2] 33 0b [2] 0e }

  condition:
    any of them
}