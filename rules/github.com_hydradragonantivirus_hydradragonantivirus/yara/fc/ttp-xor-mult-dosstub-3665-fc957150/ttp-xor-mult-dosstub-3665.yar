rule TTP_XOR_MULT_DOSStub_3665 {
  strings:
    $key_3665 = { 62 0d [2] 16 15 [2] 51 17 [2] 16 06 [2] 58 0a [2] 54 00 [2] 43 0b [2] 58 45 [2] 65 }

  condition:
    any of them
}