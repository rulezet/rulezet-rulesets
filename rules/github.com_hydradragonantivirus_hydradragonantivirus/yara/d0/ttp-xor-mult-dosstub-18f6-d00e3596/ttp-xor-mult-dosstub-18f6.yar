rule TTP_XOR_MULT_DOSStub_18f6 {
  strings:
    $key_18f6 = { 4c 9e [2] 38 86 [2] 7f 84 [2] 38 95 [2] 76 99 [2] 7a 93 [2] 6d 98 [2] 76 d6 [2] 4b }

  condition:
    any of them
}