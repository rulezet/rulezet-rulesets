rule TTP_XOR_MULT_DOSStub_4d17 {
  strings:
    $key_4d17 = { 19 7f [2] 6d 67 [2] 2a 65 [2] 6d 74 [2] 23 78 [2] 2f 72 [2] 38 79 [2] 23 37 [2] 1e }

  condition:
    any of them
}