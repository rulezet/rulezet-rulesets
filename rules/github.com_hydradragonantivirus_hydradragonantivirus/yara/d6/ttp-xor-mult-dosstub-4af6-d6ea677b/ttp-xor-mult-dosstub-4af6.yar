rule TTP_XOR_MULT_DOSStub_4af6 {
  strings:
    $key_4af6 = { 1e 9e [2] 6a 86 [2] 2d 84 [2] 6a 95 [2] 24 99 [2] 28 93 [2] 3f 98 [2] 24 d6 [2] 19 }

  condition:
    any of them
}