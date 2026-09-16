rule TTP_XOR_MULT_DOSStub_5ff6 {
  strings:
    $key_5ff6 = { 0b 9e [2] 7f 86 [2] 38 84 [2] 7f 95 [2] 31 99 [2] 3d 93 [2] 2a 98 [2] 31 d6 [2] 0c }

  condition:
    any of them
}