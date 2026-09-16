rule TTP_XOR_MULT_DOSStub_3ff6 {
  strings:
    $key_3ff6 = { 6b 9e [2] 1f 86 [2] 58 84 [2] 1f 95 [2] 51 99 [2] 5d 93 [2] 4a 98 [2] 51 d6 [2] 6c }

  condition:
    any of them
}