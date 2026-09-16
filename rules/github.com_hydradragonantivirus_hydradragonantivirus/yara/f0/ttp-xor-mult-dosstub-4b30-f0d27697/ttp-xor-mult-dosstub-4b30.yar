rule TTP_XOR_MULT_DOSStub_4b30 {
  strings:
    $key_4b30 = { 1f 58 [2] 6b 40 [2] 2c 42 [2] 6b 53 [2] 25 5f [2] 29 55 [2] 3e 5e [2] 25 10 [2] 18 }

  condition:
    any of them
}