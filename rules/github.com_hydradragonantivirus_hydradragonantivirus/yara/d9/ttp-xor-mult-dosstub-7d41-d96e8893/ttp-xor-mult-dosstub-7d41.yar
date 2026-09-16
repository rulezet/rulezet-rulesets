rule TTP_XOR_MULT_DOSStub_7d41 {
  strings:
    $key_7d41 = { 29 29 [2] 5d 31 [2] 1a 33 [2] 5d 22 [2] 13 2e [2] 1f 24 [2] 08 2f [2] 13 61 [2] 2e }

  condition:
    any of them
}