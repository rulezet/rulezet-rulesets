rule TTP_XOR_MULT_DOSStub_7cf6 {
  strings:
    $key_7cf6 = { 28 9e [2] 5c 86 [2] 1b 84 [2] 5c 95 [2] 12 99 [2] 1e 93 [2] 09 98 [2] 12 d6 [2] 2f }

  condition:
    any of them
}