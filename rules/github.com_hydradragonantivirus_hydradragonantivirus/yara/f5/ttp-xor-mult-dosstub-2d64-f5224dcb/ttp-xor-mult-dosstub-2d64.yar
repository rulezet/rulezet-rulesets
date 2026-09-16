rule TTP_XOR_MULT_DOSStub_2d64 {
  strings:
    $key_2d64 = { 79 0c [2] 0d 14 [2] 4a 16 [2] 0d 07 [2] 43 0b [2] 4f 01 [2] 58 0a [2] 43 44 [2] 7e }

  condition:
    any of them
}