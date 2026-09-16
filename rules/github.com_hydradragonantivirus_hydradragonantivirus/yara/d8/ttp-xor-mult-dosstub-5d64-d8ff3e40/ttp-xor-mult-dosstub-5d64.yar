rule TTP_XOR_MULT_DOSStub_5d64 {
  strings:
    $key_5d64 = { 09 0c [2] 7d 14 [2] 3a 16 [2] 7d 07 [2] 33 0b [2] 3f 01 [2] 28 0a [2] 33 44 [2] 0e }

  condition:
    any of them
}