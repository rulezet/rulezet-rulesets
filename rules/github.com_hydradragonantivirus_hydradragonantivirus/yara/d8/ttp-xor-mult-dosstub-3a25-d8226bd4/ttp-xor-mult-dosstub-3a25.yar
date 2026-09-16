rule TTP_XOR_MULT_DOSStub_3a25 {
  strings:
    $key_3a25 = { 6e 4d [2] 1a 55 [2] 5d 57 [2] 1a 46 [2] 54 4a [2] 58 40 [2] 4f 4b [2] 54 05 [2] 69 }

  condition:
    any of them
}