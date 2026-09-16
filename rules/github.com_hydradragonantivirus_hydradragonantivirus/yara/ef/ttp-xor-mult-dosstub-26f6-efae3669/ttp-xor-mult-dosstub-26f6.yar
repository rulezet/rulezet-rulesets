rule TTP_XOR_MULT_DOSStub_26f6 {
  strings:
    $key_26f6 = { 72 9e [2] 06 86 [2] 41 84 [2] 06 95 [2] 48 99 [2] 44 93 [2] 53 98 [2] 48 d6 [2] 75 }

  condition:
    any of them
}