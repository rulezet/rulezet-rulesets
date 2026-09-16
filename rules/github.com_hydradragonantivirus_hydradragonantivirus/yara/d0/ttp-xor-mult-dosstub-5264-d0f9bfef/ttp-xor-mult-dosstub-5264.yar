rule TTP_XOR_MULT_DOSStub_5264 {
  strings:
    $key_5264 = { 06 0c [2] 72 14 [2] 35 16 [2] 72 07 [2] 3c 0b [2] 30 01 [2] 27 0a [2] 3c 44 [2] 01 }

  condition:
    any of them
}