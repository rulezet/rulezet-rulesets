rule TTP_XOR_MULT_DOSStub_1a25 {
  strings:
    $key_1a25 = { 4e 4d [2] 3a 55 [2] 7d 57 [2] 3a 46 [2] 74 4a [2] 78 40 [2] 6f 4b [2] 74 05 [2] 49 }

  condition:
    any of them
}