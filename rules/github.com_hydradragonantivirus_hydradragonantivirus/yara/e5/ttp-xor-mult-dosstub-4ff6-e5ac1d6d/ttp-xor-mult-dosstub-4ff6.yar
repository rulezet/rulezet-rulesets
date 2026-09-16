rule TTP_XOR_MULT_DOSStub_4ff6 {
  strings:
    $key_4ff6 = { 1b 9e [2] 6f 86 [2] 28 84 [2] 6f 95 [2] 21 99 [2] 2d 93 [2] 3a 98 [2] 21 d6 [2] 1c }

  condition:
    any of them
}