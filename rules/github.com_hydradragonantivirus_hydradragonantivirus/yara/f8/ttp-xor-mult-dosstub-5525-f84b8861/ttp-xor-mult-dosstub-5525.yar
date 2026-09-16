rule TTP_XOR_MULT_DOSStub_5525 {
  strings:
    $key_5525 = { 01 4d [2] 75 55 [2] 32 57 [2] 75 46 [2] 3b 4a [2] 37 40 [2] 20 4b [2] 3b 05 [2] 06 }

  condition:
    any of them
}