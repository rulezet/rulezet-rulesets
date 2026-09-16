rule TTP_XOR_MULT_DOSStub_3df6 {
  strings:
    $key_3df6 = { 69 9e [2] 1d 86 [2] 5a 84 [2] 1d 95 [2] 53 99 [2] 5f 93 [2] 48 98 [2] 53 d6 [2] 6e }

  condition:
    any of them
}