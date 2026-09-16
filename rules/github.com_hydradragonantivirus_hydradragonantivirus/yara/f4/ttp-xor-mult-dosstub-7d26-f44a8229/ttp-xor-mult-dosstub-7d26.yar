rule TTP_XOR_MULT_DOSStub_7d26 {
  strings:
    $key_7d26 = { 29 4e [2] 5d 56 [2] 1a 54 [2] 5d 45 [2] 13 49 [2] 1f 43 [2] 08 48 [2] 13 06 [2] 2e }

  condition:
    any of them
}