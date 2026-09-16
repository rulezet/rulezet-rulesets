rule TTP_XOR_MULT_DOSStub_7d37 {
  strings:
    $key_7d37 = { 29 5f [2] 5d 47 [2] 1a 45 [2] 5d 54 [2] 13 58 [2] 1f 52 [2] 08 59 [2] 13 17 [2] 2e }

  condition:
    any of them
}