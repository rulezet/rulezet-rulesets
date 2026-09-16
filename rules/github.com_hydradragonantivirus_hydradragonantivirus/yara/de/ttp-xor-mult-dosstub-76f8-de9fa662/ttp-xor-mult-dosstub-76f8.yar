rule TTP_XOR_MULT_DOSStub_76f8 {
  strings:
    $key_76f8 = { 22 90 [2] 56 88 [2] 11 8a [2] 56 9b [2] 18 97 [2] 14 9d [2] 03 96 [2] 18 d8 [2] 25 }

  condition:
    any of them
}