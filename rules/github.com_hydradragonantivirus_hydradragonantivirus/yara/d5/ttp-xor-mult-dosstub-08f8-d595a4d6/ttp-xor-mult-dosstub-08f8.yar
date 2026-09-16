rule TTP_XOR_MULT_DOSStub_08f8 {
  strings:
    $key_08f8 = { 5c 90 [2] 28 88 [2] 6f 8a [2] 28 9b [2] 66 97 [2] 6a 9d [2] 7d 96 [2] 66 d8 [2] 5b }

  condition:
    any of them
}