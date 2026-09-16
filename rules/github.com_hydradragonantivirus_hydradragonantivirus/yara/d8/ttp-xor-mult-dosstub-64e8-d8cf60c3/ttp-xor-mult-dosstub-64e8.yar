rule TTP_XOR_MULT_DOSStub_64e8 {
  strings:
    $key_64e8 = { 30 80 [2] 44 98 [2] 03 9a [2] 44 8b [2] 0a 87 [2] 06 8d [2] 11 86 [2] 0a c8 [2] 37 }

  condition:
    any of them
}