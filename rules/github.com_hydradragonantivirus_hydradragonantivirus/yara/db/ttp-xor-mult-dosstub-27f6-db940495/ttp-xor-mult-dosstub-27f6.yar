rule TTP_XOR_MULT_DOSStub_27f6 {
  strings:
    $key_27f6 = { 73 9e [2] 07 86 [2] 40 84 [2] 07 95 [2] 49 99 [2] 45 93 [2] 52 98 [2] 49 d6 [2] 74 }

  condition:
    any of them
}