rule TTP_XOR_MULT_DOSStub_4d30 {
  strings:
    $key_4d30 = { 19 58 [2] 6d 40 [2] 2a 42 [2] 6d 53 [2] 23 5f [2] 2f 55 [2] 38 5e [2] 23 10 [2] 1e }

  condition:
    any of them
}