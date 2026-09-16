rule TTP_XOR_MULT_DOSStub_7de7 {
  strings:
    $key_7de7 = { 29 8f [2] 5d 97 [2] 1a 95 [2] 5d 84 [2] 13 88 [2] 1f 82 [2] 08 89 [2] 13 c7 [2] 2e }

  condition:
    any of them
}