rule TTP_XOR_MULT_DOSStub_4f79 {
  strings:
    $key_4f79 = { 1b 11 [2] 6f 09 [2] 28 0b [2] 6f 1a [2] 21 16 [2] 2d 1c [2] 3a 17 [2] 21 59 [2] 1c }

  condition:
    any of them
}