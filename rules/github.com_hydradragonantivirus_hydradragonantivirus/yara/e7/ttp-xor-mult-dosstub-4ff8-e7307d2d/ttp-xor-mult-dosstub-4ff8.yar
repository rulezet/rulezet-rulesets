rule TTP_XOR_MULT_DOSStub_4ff8 {
  strings:
    $key_4ff8 = { 1b 90 [2] 6f 88 [2] 28 8a [2] 6f 9b [2] 21 97 [2] 2d 9d [2] 3a 96 [2] 21 d8 [2] 1c }

  condition:
    any of them
}