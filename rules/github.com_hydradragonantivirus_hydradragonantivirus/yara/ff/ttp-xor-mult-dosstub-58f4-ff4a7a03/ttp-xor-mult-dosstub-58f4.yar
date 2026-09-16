rule TTP_XOR_MULT_DOSStub_58f4 {
  strings:
    $key_58f4 = { 0c 9c [2] 78 84 [2] 3f 86 [2] 78 97 [2] 36 9b [2] 3a 91 [2] 2d 9a [2] 36 d4 [2] 0b }

  condition:
    any of them
}