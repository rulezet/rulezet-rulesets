rule TTP_XOR_MULT_DOSStub_6659 {
  strings:
    $key_6659 = { 32 31 [2] 46 29 [2] 01 2b [2] 46 3a [2] 08 36 [2] 04 3c [2] 13 37 [2] 08 79 [2] 35 }

  condition:
    any of them
}