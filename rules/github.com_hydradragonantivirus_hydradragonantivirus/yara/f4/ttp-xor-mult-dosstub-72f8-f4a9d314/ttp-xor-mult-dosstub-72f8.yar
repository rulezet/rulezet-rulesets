rule TTP_XOR_MULT_DOSStub_72f8 {
  strings:
    $key_72f8 = { 26 90 [2] 52 88 [2] 15 8a [2] 52 9b [2] 1c 97 [2] 10 9d [2] 07 96 [2] 1c d8 [2] 21 }

  condition:
    any of them
}