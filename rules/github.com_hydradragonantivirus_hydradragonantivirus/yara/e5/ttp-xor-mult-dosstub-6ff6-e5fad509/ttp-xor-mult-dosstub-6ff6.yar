rule TTP_XOR_MULT_DOSStub_6ff6 {
  strings:
    $key_6ff6 = { 3b 9e [2] 4f 86 [2] 08 84 [2] 4f 95 [2] 01 99 [2] 0d 93 [2] 1a 98 [2] 01 d6 [2] 3c }

  condition:
    any of them
}