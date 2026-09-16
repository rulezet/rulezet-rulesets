rule TTP_XOR_MULT_DOSStub_7af6 {
  strings:
    $key_7af6 = { 2e 9e [2] 5a 86 [2] 1d 84 [2] 5a 95 [2] 14 99 [2] 18 93 [2] 0f 98 [2] 14 d6 [2] 29 }

  condition:
    any of them
}