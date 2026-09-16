rule TTP_XOR_MULT_DOSStub_4d40 {
  strings:
    $key_4d40 = { 19 28 [2] 6d 30 [2] 2a 32 [2] 6d 23 [2] 23 2f [2] 2f 25 [2] 38 2e [2] 23 60 [2] 1e }

  condition:
    any of them
}