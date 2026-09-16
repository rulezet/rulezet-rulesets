rule TTP_XOR_MULT_DOSStub_7d67 {
  strings:
    $key_7d67 = { 29 0f [2] 5d 17 [2] 1a 15 [2] 5d 04 [2] 13 08 [2] 1f 02 [2] 08 09 [2] 13 47 [2] 2e }

  condition:
    any of them
}