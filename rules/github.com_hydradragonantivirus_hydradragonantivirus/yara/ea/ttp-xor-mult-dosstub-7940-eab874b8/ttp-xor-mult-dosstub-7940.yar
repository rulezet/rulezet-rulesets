rule TTP_XOR_MULT_DOSStub_7940 {
  strings:
    $key_7940 = { 2d 28 [2] 59 30 [2] 1e 32 [2] 59 23 [2] 17 2f [2] 1b 25 [2] 0c 2e [2] 17 60 [2] 2a }

  condition:
    any of them
}