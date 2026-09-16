rule TTP_XOR_MULT_DOSStub_28f6 {
  strings:
    $key_28f6 = { 7c 9e [2] 08 86 [2] 4f 84 [2] 08 95 [2] 46 99 [2] 4a 93 [2] 5d 98 [2] 46 d6 [2] 7b }

  condition:
    any of them
}