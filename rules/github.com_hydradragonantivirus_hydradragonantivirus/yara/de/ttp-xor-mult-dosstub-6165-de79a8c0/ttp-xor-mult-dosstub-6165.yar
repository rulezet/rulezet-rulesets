rule TTP_XOR_MULT_DOSStub_6165 {
  strings:
    $key_6165 = { 35 0d [2] 41 15 [2] 06 17 [2] 41 06 [2] 0f 0a [2] 03 00 [2] 14 0b [2] 0f 45 [2] 32 }

  condition:
    any of them
}