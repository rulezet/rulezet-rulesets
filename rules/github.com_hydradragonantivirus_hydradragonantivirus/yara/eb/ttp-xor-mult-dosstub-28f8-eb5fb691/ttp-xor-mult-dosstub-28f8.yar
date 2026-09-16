rule TTP_XOR_MULT_DOSStub_28f8 {
  strings:
    $key_28f8 = { 7c 90 [2] 08 88 [2] 4f 8a [2] 08 9b [2] 46 97 [2] 4a 9d [2] 5d 96 [2] 46 d8 [2] 7b }

  condition:
    any of them
}