rule TTP_XOR_MULT_DOSStub_1a68 {
  strings:
    $key_1a68 = { 4e 00 [2] 3a 18 [2] 7d 1a [2] 3a 0b [2] 74 07 [2] 78 0d [2] 6f 06 [2] 74 48 [2] 49 }

  condition:
    any of them
}