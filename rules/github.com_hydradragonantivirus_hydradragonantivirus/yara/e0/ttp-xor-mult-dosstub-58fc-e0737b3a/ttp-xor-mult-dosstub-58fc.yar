rule TTP_XOR_MULT_DOSStub_58fc {
  strings:
    $key_58fc = { 0c 94 [2] 78 8c [2] 3f 8e [2] 78 9f [2] 36 93 [2] 3a 99 [2] 2d 92 [2] 36 dc [2] 0b }

  condition:
    any of them
}