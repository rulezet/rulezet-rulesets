rule TTP_XOR_MULT_DOSStub_5063 {
  strings:
    $key_5063 = { 04 0b [2] 70 13 [2] 37 11 [2] 70 00 [2] 3e 0c [2] 32 06 [2] 25 0d [2] 3e 43 [2] 03 }

  condition:
    any of them
}