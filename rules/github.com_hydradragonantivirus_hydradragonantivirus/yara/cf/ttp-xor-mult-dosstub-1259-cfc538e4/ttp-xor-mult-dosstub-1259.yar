rule TTP_XOR_MULT_DOSStub_1259 {
  strings:
    $key_1259 = { 46 31 [2] 32 29 [2] 75 2b [2] 32 3a [2] 7c 36 [2] 70 3c [2] 67 37 [2] 7c 79 [2] 41 }

  condition:
    any of them
}