rule TTP_XOR_MULT_DOSStub_2d54 {
  strings:
    $key_2d54 = { 79 3c [2] 0d 24 [2] 4a 26 [2] 0d 37 [2] 43 3b [2] 4f 31 [2] 58 3a [2] 43 74 [2] 7e }

  condition:
    any of them
}