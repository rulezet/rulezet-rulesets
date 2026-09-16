rule TTP_XOR_MULT_DOSStub_05f6 {
  strings:
    $key_05f6 = { 51 9e [2] 25 86 [2] 62 84 [2] 25 95 [2] 6b 99 [2] 67 93 [2] 70 98 [2] 6b d6 [2] 56 }

  condition:
    any of them
}