rule TTP_XOR_MULT_DOSStub_4d37 {
  strings:
    $key_4d37 = { 19 5f [2] 6d 47 [2] 2a 45 [2] 6d 54 [2] 23 58 [2] 2f 52 [2] 38 59 [2] 23 17 [2] 1e }

  condition:
    any of them
}