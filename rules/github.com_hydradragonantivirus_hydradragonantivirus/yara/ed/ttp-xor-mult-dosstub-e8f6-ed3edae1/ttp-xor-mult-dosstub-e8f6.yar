rule TTP_XOR_MULT_DOSStub_e8f6 {
  strings:
    $key_e8f6 = { bc 9e [2] c8 86 [2] 8f 84 [2] c8 95 [2] 86 99 [2] 8a 93 [2] 9d 98 [2] 86 d6 [2] bb }

  condition:
    any of them
}