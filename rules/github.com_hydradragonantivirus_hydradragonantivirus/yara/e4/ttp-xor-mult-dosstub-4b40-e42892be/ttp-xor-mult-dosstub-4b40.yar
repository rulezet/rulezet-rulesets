rule TTP_XOR_MULT_DOSStub_4b40 {
  strings:
    $key_4b40 = { 1f 28 [2] 6b 30 [2] 2c 32 [2] 6b 23 [2] 25 2f [2] 29 25 [2] 3e 2e [2] 25 60 [2] 18 }

  condition:
    any of them
}