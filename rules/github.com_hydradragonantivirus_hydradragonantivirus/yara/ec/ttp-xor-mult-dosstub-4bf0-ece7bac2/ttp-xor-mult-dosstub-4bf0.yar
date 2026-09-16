rule TTP_XOR_MULT_DOSStub_4bf0 {
  strings:
    $key_4bf0 = { 1f 98 [2] 6b 80 [2] 2c 82 [2] 6b 93 [2] 25 9f [2] 29 95 [2] 3e 9e [2] 25 d0 [2] 18 }

  condition:
    any of them
}