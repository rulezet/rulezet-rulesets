rule TTP_XOR_MULT_DOSStub_5861 {
  strings:
    $key_5861 = { 0c 09 [2] 78 11 [2] 3f 13 [2] 78 02 [2] 36 0e [2] 3a 04 [2] 2d 0f [2] 36 41 [2] 0b }

  condition:
    any of them
}