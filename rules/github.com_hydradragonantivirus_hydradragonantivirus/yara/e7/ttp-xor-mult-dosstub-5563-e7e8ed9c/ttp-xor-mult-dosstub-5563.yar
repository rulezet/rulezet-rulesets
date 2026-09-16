rule TTP_XOR_MULT_DOSStub_5563 {
  strings:
    $key_5563 = { 01 0b [2] 75 13 [2] 32 11 [2] 75 00 [2] 3b 0c [2] 37 06 [2] 20 0d [2] 3b 43 [2] 06 }

  condition:
    any of them
}