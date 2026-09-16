rule TTP_XOR_MULT_DOSStub_1a79 {
  strings:
    $key_1a79 = { 4e 11 [2] 3a 09 [2] 7d 0b [2] 3a 1a [2] 74 16 [2] 78 1c [2] 6f 17 [2] 74 59 [2] 49 }

  condition:
    any of them
}