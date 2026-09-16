rule TTP_XOR_MULT_DOSStub_7af8 {
  strings:
    $key_7af8 = { 2e 90 [2] 5a 88 [2] 1d 8a [2] 5a 9b [2] 14 97 [2] 18 9d [2] 0f 96 [2] 14 d8 [2] 29 }

  condition:
    any of them
}