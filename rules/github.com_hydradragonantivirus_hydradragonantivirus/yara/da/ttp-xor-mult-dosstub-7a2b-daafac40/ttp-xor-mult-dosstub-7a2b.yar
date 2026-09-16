rule TTP_XOR_MULT_DOSStub_7a2b {
  strings:
    $key_7a2b = { 2e 43 [2] 5a 5b [2] 1d 59 [2] 5a 48 [2] 14 44 [2] 18 4e [2] 0f 45 [2] 14 0b [2] 29 }

  condition:
    any of them
}