rule TTP_XOR_MULT_DOSStub_7d76 {
  strings:
    $key_7d76 = { 29 1e [2] 5d 06 [2] 1a 04 [2] 5d 15 [2] 13 19 [2] 1f 13 [2] 08 18 [2] 13 56 [2] 2e }

  condition:
    any of them
}