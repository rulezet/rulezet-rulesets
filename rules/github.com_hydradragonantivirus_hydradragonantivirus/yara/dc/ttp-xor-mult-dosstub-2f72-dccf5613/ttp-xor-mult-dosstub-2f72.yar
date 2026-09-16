rule TTP_XOR_MULT_DOSStub_2f72 {
  strings:
    $key_2f72 = { 7b 1a [2] 0f 02 [2] 48 00 [2] 0f 11 [2] 41 1d [2] 4d 17 [2] 5a 1c [2] 41 52 [2] 7c }

  condition:
    any of them
}