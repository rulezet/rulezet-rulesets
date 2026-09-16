rule TTP_XOR_MULT_DOSStub_5827 {
  strings:
    $key_5827 = { 0c 4f [2] 78 57 [2] 3f 55 [2] 78 44 [2] 36 48 [2] 3a 42 [2] 2d 49 [2] 36 07 [2] 0b }

  condition:
    any of them
}