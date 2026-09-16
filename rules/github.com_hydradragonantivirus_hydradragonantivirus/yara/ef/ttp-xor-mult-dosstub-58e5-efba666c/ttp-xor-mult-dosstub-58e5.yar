rule TTP_XOR_MULT_DOSStub_58e5 {
  strings:
    $key_58e5 = { 0c 8d [2] 78 95 [2] 3f 97 [2] 78 86 [2] 36 8a [2] 3a 80 [2] 2d 8b [2] 36 c5 [2] 0b }

  condition:
    any of them
}