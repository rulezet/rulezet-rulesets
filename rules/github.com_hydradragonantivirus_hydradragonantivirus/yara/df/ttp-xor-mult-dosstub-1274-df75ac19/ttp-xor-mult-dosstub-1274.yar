rule TTP_XOR_MULT_DOSStub_1274 {
  strings:
    $key_1274 = { 46 1c [2] 32 04 [2] 75 06 [2] 32 17 [2] 7c 1b [2] 70 11 [2] 67 1a [2] 7c 54 [2] 41 }

  condition:
    any of them
}