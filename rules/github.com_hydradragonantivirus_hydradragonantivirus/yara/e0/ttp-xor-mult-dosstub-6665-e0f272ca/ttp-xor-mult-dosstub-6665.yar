rule TTP_XOR_MULT_DOSStub_6665 {
  strings:
    $key_6665 = { 32 0d [2] 46 15 [2] 01 17 [2] 46 06 [2] 08 0a [2] 04 00 [2] 13 0b [2] 08 45 [2] 35 }

  condition:
    any of them
}